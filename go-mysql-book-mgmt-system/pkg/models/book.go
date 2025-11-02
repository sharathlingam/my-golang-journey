// Package models handles the data structure and database operations for books
package models

import (
	// gorm is an ORM library for Golang, providing database operations
	"github.com/jinzhu/gorm"
	// importing our local config package that handles database connection
	"github.com/sharathlingam/go-mysql-book-mgmt-system/pkg/config"
)

// db is a package-level variable that holds the database connection
// It's accessible only within the models package
var db *gorm.DB

// Book represents the model for a book in our system
// The struct tags `gorm:"..."` tell GORM how to map struct fields to database columns
type Book struct {
	// Name of the book
	// gorm:"name" specifies the column name in the database
	Name string `gorm:"name"`

	// Author of the book
	// gorm:"author" specifies the column name in the database
	Author string `gorm:"author"`

	// Publication details of the book
	// gorm:"publication" specifies the column name in the database
	Publication string `gorm:"publication"`
}

// init is a special function in Go that runs automatically when the package is initialized
// It's used here to set up our database connection and create/update the table schema
func init() {
	// Connect to the database using configuration from config package
	config.Connect()

	// Get the database instance
	db = config.GetDB()

	// AutoMigrate will automatically create or update the table based on our Book struct
	// It creates the 'books' table if it doesn't exist, or updates its schema if it does
	db.AutoMigrate(&Book{})
}

func (b *Book) CreateBook() *Book {
	db.NewRecord(b)
	db.Create(&b)
	return b
}

func GetBooksList() []Book {
	var Books []Book
	db.Find(&Books)
	return Books
}

func GetBook(Id int64) (*Book, *gorm.DB) {

	// In GORM's Find method, we pass &book (a pointer) for several key reasons:

	// 1. The Find method needs to modify the original variable to populate it with database results
	//    If we passed the book value directly, we'd only modify a copy

	// 2. GORM uses reflection to:
	//    - Determine the struct type (to know which table to query)
	//    - Fill the struct fields with database values
	//    - Set relationships if any exist

	// Example usage:
	var book Book
	db.Where("ID=?", Id).Find(&book) // Passes pointer so GORM can modify the book variable

	// Without pointer (wouldn't work):
	// var book Book
	// db.Find(book) // ❌ Would only modify a copy, original book stays empty

	return &book, db
}

func DeleteBook(Id int64) Book {
	var book Book
	db.Where("ID=?", Id).Delete(&book)
	return book
}
