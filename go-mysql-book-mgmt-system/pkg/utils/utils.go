package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func ParseBody(r *http.Request, X interface{}) {

	if body, err := io.ReadAll(r.Body); err == nil {

		if err := json.Unmarshal([]byte(body), X); err != nil {
			return
		}

	} else {
		log.Fatal(err)
	}

}

func PrintRoute(r *http.Request) {

	fmt.Printf("Route: %v\n", r.URL)

}
