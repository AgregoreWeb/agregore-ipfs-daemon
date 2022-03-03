package api

import "net/http"

type Server struct {
	serveMux http.ServeMux
}

func NewServer() *Server {
	s := &Server{}
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.serveMux.ServeHTTP(w, r)
}
