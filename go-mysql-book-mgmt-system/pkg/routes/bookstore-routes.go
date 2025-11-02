package routes

import (
	"github.com/gorilla/mux"
	"github.com/sharathlingam/go-mysql-book-mgmt-system/pkg/controllers"
)

var RegisterBookStoreRoutes = func(router *mux.Router) {
	router.HandleFunc("/books/", controllers.GetBooksList).Methods("GET")
	router.HandleFunc("/book/", controllers.CreateBook).Methods("POST")
	router.HandleFunc("/book/{id}/", controllers.GetBook).Methods("GET")
	router.HandleFunc("/book/{id}/", controllers.UpdateBook).Methods("PUT")
	router.HandleFunc("/book/{id}/", controllers.DeleteBook).Methods("DELETE")
}
