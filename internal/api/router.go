package api

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers all API v1 routes on the given router group.
// The group should already have rate limiting middleware applied.
func (h *Handler) RegisterRoutes(r *gin.Engine, rateLimitMiddleware gin.HandlerFunc) {
	apiV1 := r.Group("/api/v1")
	apiV1.Use(h.APIKeyAuthMiddleware())
	if rateLimitMiddleware != nil {
		apiV1.Use(rateLimitMiddleware)
	}

	sessions := apiV1.Group("/sessions")
	{
		sessions.POST("", h.CreateSession)
		sessions.GET("", h.ListSessions)

		// Per-session routes require session key validation
		sessionByID := sessions.Group("/:id")
		sessionByID.Use(h.sessionKeyMiddleware())
		{
			sessionByID.GET("", h.GetSession)
			sessionByID.DELETE("", h.CloseSession)
			sessionByID.POST("/exec", h.ExecCommand)
			sessionByID.GET("/attach", h.AttachSession)
		}
	}
}
