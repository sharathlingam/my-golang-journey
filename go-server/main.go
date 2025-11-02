package main

import (
	"fmt"
	"log"
	"net/http"
)

func formHandler(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}

	fmt.Fprintf(w, "POST request succesfull\n")
	name := r.FormValue("name")
	email := r.FormValue("email")
	message := r.FormValue("message")

	fmt.Fprintf(w, "Name: %s\nEmail: %s\nMessage: %s", name, email, message)

}

func helloHandler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/hello" {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprintf(w, "Hello There!")

}

func main() {

	fileServer := http.FileServer(http.Dir("./static"))

	http.Handle("/", fileServer)

	http.HandleFunc("/form", formHandler)

	http.HandleFunc("/hello", helloHandler)

	fmt.Printf("Starting server at port 8080...\n")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}

}
