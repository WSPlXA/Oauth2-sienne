package dto

type ConsentDecisionRequest struct {
	Action   string `json:"action" form:"action" binding:"required"`
	ReturnTo string `json:"return_to" form:"return_to" binding:"required"`
}
