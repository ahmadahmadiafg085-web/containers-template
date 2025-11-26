package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func env(k, fallback string) string {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	return v
}

func handler(w http.ResponseWriter, r *http.Request) {
	message := env("MESSAGE", "Default message")
	instanceId := env("INSTANCE_ID", "no-instance")
	fmt.Fprintf(w, `{"status":"ok","message":"%s","instance":"%s"}`, message, instanceId)
}

func health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"health":"ok"}`))
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	panic("panic test")
}

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/error", errorHandler)

	server := &http.Server{
		Addr:    env("PORT", ":8080"),
		Handler: mux,
	}

	go func() {
		log.Printf("server started on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	sig := <-stop
	log.Printf("shutdown triggered: %v", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}

	log.Println("server gracefully stopped")
}
