package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

type Movie struct {
	ID       string    `json:"id"`
	Isbn     string    `json:"isbn"`
	Title    string    `json:"title"`
	Director *Director `json:"director"`
}

type Director struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

func getMovies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(movies)
}

func deleteMovie(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for index, item := range movies {
		if item.ID == params["id"] {
			movies = append(movies[:index], movies[index+1:]...)
			break
		}
	}

	json.NewEncoder(w).Encode(movies)
}

func getMovie(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for _, item := range movies {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
}

func createMovie(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var movie Movie
	if err := json.NewDecoder(r.Body).Decode(&movie); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	movie.ID = strconv.Itoa(rand.Intn(100000000))
	movies = append(movies, movie)
	json.NewEncoder(w).Encode(movies)
}

func updateMovie(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	id := params["id"]
	// We should get the body value of movie to update,
	// Should get the index of that id and then change the values inside it
	// After changing, attach the movie in the same index and return the json object back

	var movie Movie
	if err := json.NewDecoder(r.Body).Decode(&movie); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	for idx, item := range movies {
		if id == item.ID {
			movie.ID = item.ID
			movies = append(movies[:idx], movies[idx+1:]...)
			movies = append(movies, movie)
		}
	}
	json.NewEncoder(w).Encode(movies)
}

var movies []Movie

func main() {

	r := mux.NewRouter()

	movies = append(movies,
		Movie{
			ID:       "1",
			Isbn:     "438227",
			Title:    "The Shawshank Redemption",
			Director: &Director{FirstName: "Frank", LastName: "Darabont"},
		},
		Movie{
			ID:       "2",
			Isbn:     "454555",
			Title:    "The Godfather",
			Director: &Director{FirstName: "Francis", LastName: "Coppola"},
		},
		Movie{
			ID:       "3",
			Isbn:     "557821",
			Title:    "The Dark Knight",
			Director: &Director{FirstName: "Christopher", LastName: "Nolan"},
		},
		Movie{
			ID:       "4",
			Isbn:     "445793",
			Title:    "Pulp Fiction",
			Director: &Director{FirstName: "Quentin", LastName: "Tarantino"},
		},
		Movie{
			ID:       "5",
			Isbn:     "679231",
			Title:    "Inception",
			Director: &Director{FirstName: "Christopher", LastName: "Nolan"},
		})

	r.HandleFunc("/movies", getMovies).Methods("GET")
	r.HandleFunc("/movies/{id}", getMovie).Methods("GET")
	r.HandleFunc("/movies", createMovie).Methods("POST")
	r.HandleFunc("/movies", updateMovie).Methods("PUT")
	r.HandleFunc("/movies/{id}", deleteMovie).Methods("DELETE")

	fmt.Printf("Starting server at port 8080...")
	log.Fatal("Error Starting the server", http.ListenAndServe(":8080", r))

}
