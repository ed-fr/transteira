// Package gen is a small fixture mimicking the oapi-codegen strict server output.
package gen

import (
	"context"

	ext "example.com/external/types"
)

type ProblemCode string

type Problem struct {
	Code   ProblemCode `json:"code"`
	Status int         `json:"status"`
	Title  string      `json:"title"`
	Type   string      `json:"type"`
}

type NotFoundApplicationProblemPlusJSONResponse Problem

type GetItemRequestObject struct{ ID ext.UUID }

type GetItemResponseObject interface{ VisitGetItemResponse() error }

type GetItem404ApplicationProblemPlusJSONResponse struct {
	NotFoundApplicationProblemPlusJSONResponse
}

type DirectRequestObject struct{}

type DirectResponseObject interface{ VisitDirectResponse() error }

type Direct404ApplicationProblemPlusJSONResponse Problem

type UploadRequestObject struct{}

type UploadResponseObject interface{ VisitUploadResponse() error }

type Upload404Response struct {
}

type PlainRequestObject struct{}

type PlainResponseObject interface{ VisitPlainResponse() error }

type StrictServerInterface interface {
	// Upload (PATCH /uploads/{id})
	Upload(ctx context.Context, request UploadRequestObject) (UploadResponseObject, error)
	// GetItem (GET /items/{id})
	GetItem(ctx context.Context, request GetItemRequestObject) (GetItemResponseObject, error)
	// Plain (GET /plain)
	Plain(ctx context.Context, request PlainRequestObject) (PlainResponseObject, error)
	// Direct (GET /direct)
	Direct(ctx context.Context, a, b ext.UUID, request DirectRequestObject) (DirectResponseObject, error)
}
