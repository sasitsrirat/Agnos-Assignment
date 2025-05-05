package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupRouterInMemory() *gin.Engine {
	// สร้าง in-memory DB
	db, _ := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	db.AutoMigrate(&Hospital{}, &Staff{}, &Patient{})

	// seed ข้อมูล
	hospID, _ := SeedHospitalAndStaffData(db)
	SeedPatientData(db, hospID)

	// สร้าง router
	r := gin.Default()
	r.POST("/staff/create", CreateStaffHandler(db))
	r.POST("/staff/login", LoginHandler(db))
	r.GET("/patient/search/:id", SearchPatientPublicHandler(db))

	internal := r.Group("/patient", AuthMiddleware())
	internal.GET("/search", SearchPatientInternalHandler(db))
	return r
}

func TestLoginAndSearch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := setupRouterInMemory()

	// 1. Login
	w := httptest.NewRecorder()
	loginBody := `{"username":"admin","password":"password123"}`
	req, _ := http.NewRequest(http.MethodPost, "/staff/login", bytes.NewBufferString(loginBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Login expected 200, got %d", w.Code)
	}

	var loginResp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatal("Expected token in login response")
	}

	// 2. Internal search by national_id
	w = httptest.NewRecorder()
	searchReq, _ := http.NewRequest(http.MethodGet, "/patient/search?national_id=1234567890123", nil)
	searchReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	r.ServeHTTP(w, searchReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Search expected 200, got %d", w.Code)
	}

	var patients []Patient
	json.Unmarshal(w.Body.Bytes(), &patients)
	if len(patients) != 1 {
		t.Fatalf("Expected 1 patient, got %d", len(patients))
	}
	if patients[0].NationalID != "1234567890123" {
		t.Errorf("Expected NationalID 1234567890123, got %s", patients[0].NationalID)
	}

	// 3. Public search
	w = httptest.NewRecorder()
	pubReq, _ := http.NewRequest(http.MethodGet, "/patient/search/9876543210987", nil)
	r.ServeHTTP(w, pubReq)
	if w.Code != http.StatusOK {
		t.Fatalf("Public search expected 200, got %d", w.Code)
	}
	var pubPatient Patient
	json.Unmarshal(w.Body.Bytes(), &pubPatient)
	if pubPatient.NationalID != "9876543210987" {
		t.Errorf("Expected NationalID 9876543210987, got %s", pubPatient.NationalID)
	}
}
