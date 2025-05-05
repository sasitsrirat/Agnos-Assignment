package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/joho/godotenv"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("your-secret-key")

type Patient struct {
	ID           string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	FirstNameTh  string    `json:"first_name_th"`
	MiddleNameTh string    `json:"middle_name_th"`
	LastNameTh   string    `json:"last_name_th"`
	FirstNameEn  string    `json:"first_name_en"`
	MiddleNameEn string    `json:"middle_name_en"`
	LastNameEn   string    `json:"last_name_en"`
	DateOfBirth  time.Time `json:"date_of_birth"`
	PatientHN    string    `json:"patient_hn"`
	NationalID   string    `json:"national_id"`
	PassportID   string    `json:"passport_id"`
	PhoneNumber  string    `json:"phone_number"`
	Email        string    `json:"email"`
	Gender       string    `json:"gender"`
	HospitalID   string    `json:"hospital_id"`
}

type Staff struct {
	ID           string `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username     string
	PasswordHash string
	HospitalID   string
}

type Hospital struct {
	ID   string `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Name string
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	StaffID    string `json:"staff_id"`
	HospitalID string `json:"hospital_id"`
	jwt.RegisteredClaims
}

func SetupDatabase() *gorm.DB {
	godotenv.Load()
	dsn := os.Getenv("DATABASE_DSN")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database")
	}
	db.AutoMigrate(&Hospital{}, &Patient{}, &Staff{})
	return db
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
		claims := token.Claims.(*Claims)
		c.Set("staff_id", claims.StaffID)
		c.Set("hospital_id", claims.HospitalID)
		c.Next()
	}
}

func CreateStaffHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username   string `json:"username"`
			Password   string `json:"password"`
			HospitalID string `json:"hospital_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		staff := Staff{
			Username:     req.Username,
			PasswordHash: string(hash),
			HospitalID:   req.HospitalID,
		}
		if err := db.Create(&staff).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create staff"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"message": "Staff created"})
	}
}

func LoginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		var staff Staff
		err := db.First(&staff, "username = ?", req.Username).Error
		if err != nil || bcrypt.CompareHashAndPassword([]byte(staff.PasswordHash), []byte(req.Password)) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
		claims := &Claims{
			StaffID:    staff.ID,
			HospitalID: staff.HospitalID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenStr})
	}
}

func SearchPatientPublicHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var patient Patient
		err := db.Where("national_id = ? OR passport_id = ?", id, id).First(&patient).Error
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Failed to fetch patient data"})
			return
		}
		c.JSON(http.StatusOK, patient)
	}
}

func SearchPatientInternalHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		hospitalID, _ := c.Get("hospital_id")
		query := db.Model(&Patient{}).Where("hospital_id = ?", hospitalID)

		if v := c.Query("national_id"); v != "" {
			query = query.Where("national_id = ?", v)
		}
		if v := c.Query("passport_id"); v != "" {
			query = query.Where("passport_id = ?", v)
		}
		if v := c.Query("first_name"); v != "" {
			query = query.Where("first_name_en ILIKE ? OR first_name_th ILIKE ?", "%"+v+"%", "%"+v+"%")
		}
		if v := c.Query("middle_name"); v != "" {
			query = query.Where("middle_name_en ILIKE ? OR middle_name_th ILIKE ?", "%"+v+"%", "%"+v+"%")
		}
		if v := c.Query("last_name"); v != "" {
			query = query.Where("last_name_en ILIKE ? OR last_name_th ILIKE ?", "%"+v+"%", "%"+v+"%")
		}
		if v := c.Query("date_of_birth"); v != "" {
			if dob, err := time.Parse("2006-01-02", v); err == nil {
				query = query.Where("date_of_birth = ?", dob)
			}
		}
		if v := c.Query("phone_number"); v != "" {
			query = query.Where("phone_number = ?", v)
		}
		if v := c.Query("email"); v != "" {
			query = query.Where("email ILIKE ?", "%"+v+"%")
		}

		var patients []Patient
		if err := query.Find(&patients).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Search failed"})
			return
		}
		c.JSON(http.StatusOK, patients)
	}
}

func SeedHospitalAndStaffData(db *gorm.DB) (string, string) {
	// Seed Hospital
	hospital := Hospital{
		Name: "โรงพยาบาลตัวอย่าง",
	}
	if err := db.FirstOrCreate(&hospital, Hospital{Name: hospital.Name}).Error; err != nil {
		log.Fatal("Failed to seed hospital:", err)
	}

	// Seed Staff
	password := "password123"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	staff := Staff{
		Username:     "admin",
		PasswordHash: string(hash),
		HospitalID:   hospital.ID,
	}
	if err := db.FirstOrCreate(&staff, Staff{Username: staff.Username}).Error; err != nil {
		log.Fatal("Failed to seed staff:", err)
	}

	log.Println("Seeded hospital and staff")
	log.Println("Staff login username: admin")
	log.Println("Staff login password:", password)

	return hospital.ID, staff.ID
}

func SeedPatientData(db *gorm.DB, hospitalID string) {
	patients := []Patient{
		{
			FirstNameTh: "สมชาย",
			LastNameTh:  "ใจดี",
			FirstNameEn: "Somchai",
			LastNameEn:  "Jaidee",
			DateOfBirth: time.Date(1990, 5, 10, 0, 0, 0, 0, time.UTC),
			PatientHN:   "HN001",
			NationalID:  "1234567890123",
			PhoneNumber: "0812345678",
			Email:       "somchai@example.com",
			Gender:      "male",
			HospitalID:  hospitalID,
		},
		{
			FirstNameTh: "มานี",
			LastNameTh:  "ใจเย็น",
			FirstNameEn: "Manee",
			LastNameEn:  "Jaiyen",
			DateOfBirth: time.Date(1985, 12, 25, 0, 0, 0, 0, time.UTC),
			PatientHN:   "HN002",
			NationalID:  "9876543210987",
			PhoneNumber: "0898765432",
			Email:       "manee@example.com",
			Gender:      "female",
			HospitalID:  hospitalID,
		},
	}

	for _, p := range patients {
		db.FirstOrCreate(&p, Patient{NationalID: p.NationalID})
	}
	log.Println("Seeded patients")
}

func main() {
	db := SetupDatabase()

	hospitalID, _ := SeedHospitalAndStaffData(db)
	SeedPatientData(db, hospitalID)

	r := gin.Default()

	r.POST("/staff/create", CreateStaffHandler(db))
	r.POST("/staff/login", LoginHandler(db))
	r.GET("/patient/search/:id", SearchPatientPublicHandler(db))

	internal := r.Group("/patient", AuthMiddleware())
	internal.GET("/search", SearchPatientInternalHandler(db))

	r.Run(":8080")
}
