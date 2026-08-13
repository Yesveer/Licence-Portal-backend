package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"license-portal-backend/internal/models"
)

/* ───────────── Portal user management (superadmin only) ─────────────
   Two roles: superadmin (full access) and admin (team member —
   no SMTP settings, no audit log, no user management). */

func validRole(r string) bool {
	return r == models.RoleSuperadmin || r == models.RoleAdmin
}

func (h *Handler) ListUsers(c *gin.Context) {
	ctx, cancel := reqCtx(c)
	defer cancel()

	cur, err := h.Store.C("admin_users").Find(ctx, bson.M{},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	var users []models.AdminUser
	if err := cur.All(ctx, &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "decode failed"})
		return
	}
	for i := range users {
		if users[i].Role == "" {
			users[i].Role = models.RoleSuperadmin
		}
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (h *Handler) CreateUser(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role == "" {
		req.Role = models.RoleAdmin
	}
	if !validRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be superadmin or admin"})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}
	actor := c.GetString("admin_email")
	user := models.AdminUser{
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         req.Role,
		CreatedBy:    actor,
		CreatedAt:    time.Now().UTC(),
	}
	res, err := h.Store.C("admin_users").InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "a user with this email already exists"})
		return
	}
	user.ID = res.InsertedID.(primitive.ObjectID)
	h.audit(actor, "create_user", req.Email, req.Role)
	c.JSON(http.StatusCreated, gin.H{"user": user})
}

func (h *Handler) UpdateUser(c *gin.Context) {
	var req struct {
		Role     *string `json:"role"`
		Password *string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	var user models.AdminUser
	if err := h.Store.C("admin_users").FindOne(ctx, bson.M{"_id": id}).Decode(&user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	actor := c.GetString("admin_email")
	set := bson.M{}

	if req.Role != nil && *req.Role != user.Role {
		if !validRole(*req.Role) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "role must be superadmin or admin"})
			return
		}
		// never demote the last superadmin
		if user.Role == models.RoleSuperadmin && *req.Role != models.RoleSuperadmin {
			count, _ := h.Store.C("admin_users").CountDocuments(ctx, bson.M{"role": models.RoleSuperadmin})
			if count <= 1 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "cannot demote the last superadmin"})
				return
			}
		}
		set["role"] = *req.Role
		h.audit(actor, "change_user_role", user.Email, *req.Role)
	}
	if req.Password != nil {
		if len(*req.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		set["password_hash"] = string(hash)
		h.audit(actor, "reset_user_password", user.Email, "")
	}
	if len(set) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nothing to update"})
		return
	}
	if _, err := h.Store.C("admin_users").UpdateByID(ctx, id, bson.M{"$set": set}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) DeleteUser(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	var user models.AdminUser
	if err := h.Store.C("admin_users").FindOne(ctx, bson.M{"_id": id}).Decode(&user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	actor := c.GetString("admin_email")
	if user.Email == actor {
		c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot delete your own account"})
		return
	}
	if user.Role == models.RoleSuperadmin {
		count, _ := h.Store.C("admin_users").CountDocuments(ctx, bson.M{"role": models.RoleSuperadmin})
		if count <= 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete the last superadmin"})
			return
		}
	}
	if _, err := h.Store.C("admin_users").DeleteOne(ctx, bson.M{"_id": id}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	h.audit(actor, "delete_user", user.Email, user.Role)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
