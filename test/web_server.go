// simple http server
// date: 2025/9/17

package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/proto", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "ming" 
		}

		time.Sleep(1 * time.Second)
		fmt.Fprintf(w, "<h1>hello %s</h1>", name)
	})

	fmt.Println("listen 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}

