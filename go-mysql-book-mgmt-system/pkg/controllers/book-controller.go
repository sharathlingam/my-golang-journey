package controllers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sharathlingam/go-mysql-book-mgmt-system/pkg/models"
	"github.com/sharathlingam/go-mysql-book-mgmt-system/pkg/utils"
)

var NewBook models.Book

func GetBooksList(w http.ResponseWriter, r *http.Request) {
	utils.PrintRoute(r)
	newBooks := models.GetBooksList()
	res, _ := json.Marshal(newBooks)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func CreateBook(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	CreateBook := &models.Book{}
	utils.ParseBody(r, CreateBook)
	book := CreateBook.CreateBook()

	val, _ := json.Marshal(book)
	w.WriteHeader(http.StatusCreated)
	w.Write(val)

}
func GetBook(w http.ResponseWriter, r *http.Request) {
	utils.PrintRoute(r)
	params := mux.Vars(r)
	w.Header().Set("Content-Type", "application/json")
	id, err := strconv.ParseInt(params["id"], 0, 0)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	book, db := models.GetBook(id)

	if db.Error != nil {
		w.WriteHeader(http.StatusNotFound)
		ret, _ := json.Marshal(db.Error)
		w.Write(ret)
		return
	}

	data, _ := json.Marshal(book)

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func UpdateBook(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)

	id, _ := strconv.ParseInt(params["id"], 0, 0)

	var UpdateBook = &models.Book{}
	utils.ParseBody(r, UpdateBook)

	bookDetails, db := models.GetBook(id)

	if bookDetails.Name != "" {
		bookDetails.Name = UpdateBook.Name
	}
	if bookDetails.Author != "" {
		bookDetails.Author = UpdateBook.Author
	}
	if bookDetails.Publication != "" {
		bookDetails.Publication = UpdateBook.Publication
	}

	db.Save(&bookDetails)

	res, _ := json.Marshal(&bookDetails)

	w.WriteHeader(http.StatusOK)
	w.Write(res)

}

func DeleteBook(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	id, _ := strconv.ParseInt(params["id"], 0, 0)

	book := models.DeleteBook(id)

	data, _ := json.Marshal(book)

	w.WriteHeader(http.StatusOK)
	w.Write(data)

}
