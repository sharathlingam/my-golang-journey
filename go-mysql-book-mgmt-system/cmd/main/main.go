package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sharathlingam/go-mysql-book-mgmt-system/pkg/routes"
)

func main() {

	r := mux.NewRouter()
	routes.RegisterBookStoreRoutes(r)
	http.Handle("/", r)
	fmt.Print("Server is running in port 9010...\n")
	log.Fatal("Error starting the server!", http.ListenAndServe(":9010", r))
}
