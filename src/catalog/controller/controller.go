// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this
// software and associated documentation files (the "Software"), to deal in the Software
// without restriction, including without limitation the rights to use, copy, modify,
// merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package controller

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/aws-containers/retail-store-sample-app/catalog/api"
	"github.com/aws-containers/retail-store-sample-app/catalog/httputil"
	"github.com/aws-containers/retail-store-sample-app/catalog/model"
	"github.com/gin-gonic/gin"
)

// Controller example
type Controller struct {
	api *api.CatalogAPI
}

// NewController example
func NewController(api *api.CatalogAPI) (*Controller, error) {
	return &Controller{
		api: api,
	}, nil
}

// GetProducts godoc
// @Summary Get catalog
// @Description Get catalog
// @Tags catalog
// @Accept  json
// @Produce  json
// @Param tags query string false "Tagged products to include"
// @Param order query string false "Order of response"
// @Param page query int false "Page number"
// @Param size query int false "Page size"
// @Success 200 {array} model.Product
// @Failure 400 {object} httputil.HTTPError
// @Failure 404 {object} httputil.HTTPError
// @Failure 500 {object} httputil.HTTPError
// @Router /catalog/products [get]
func (c *Controller) GetProducts(ctx *gin.Context) {
	var tags []string

	tagString := ctx.Query("tags")
	if len(tagString) > 0 {
		tags = strings.Split(tagString, ",")
	} else {
		tags = []string{}
	}

	order := ctx.Query("order")

	page, err := getQueryInt("page", 1, ctx)
	if err != nil {
		httputil.NewError(ctx, http.StatusBadRequest, err)
		return
	}

	size, err := getQueryInt("size", 10, ctx)
	if err != nil {
		httputil.NewError(ctx, http.StatusBadRequest, err)
		return
	}

	products, err := c.api.GetProducts(tags, order, page, size, ctx.Request.Context())
	if err != nil {
		httputil.NewError(ctx, http.StatusNotFound, err)
		return
	}
	ctx.JSON(http.StatusOK, products)
}

// GetProducts godoc
// @Summary Get catalog
// @Description Get catalog
// @Tags catalog
// @Accept  json
// @Produce  json
// @Param id path string true "product ID"
// @Success 200 {object} model.Product
// @Failure 400 {object} httputil.HTTPError
// @Failure 404 {object} httputil.HTTPError
// @Failure 500 {object} httputil.HTTPError
// @Router /catalog/products/{id} [get]
func (c *Controller) GetProduct(ctx *gin.Context) {
	id := ctx.Param("id")

	product, err := c.api.GetProduct(id, ctx.Request.Context())
	if err != nil {
		httputil.NewError(ctx, http.StatusNotFound, err)
		return
	}
	ctx.JSON(http.StatusOK, product)
}

// CatalogSize godoc
// @Summary Get catalog size
// @Description Get catalog size
// @Tags catalog
// @Accept  json
// @Produce  json
// @Param tags query string false "Tagged products to include"
// @Success 200 {object} model.CatalogSizeResponse
// @Failure 400 {object} httputil.HTTPError
// @Failure 404 {object} httputil.HTTPError
// @Failure 500 {object} httputil.HTTPError
// @Router /catalog/size [get]
func (c *Controller) CatalogSize(ctx *gin.Context) {
	var tags []string

	tagString := ctx.Query("tags")
	if len(tagString) > 0 {
		tags = strings.Split(tagString, ",")
	} else {
		tags = []string{}
	}

	count, err := c.api.GetSize(tags, ctx.Request.Context())
	if err != nil {
		httputil.NewError(ctx, http.StatusNotFound, err)
		return
	}
	ctx.JSON(http.StatusOK, model.CatalogSizeResponse{
		Size: count,
	})
}

// ListTags godoc
// @Summary List tags
// @Description get tags
// @Tags catalog
// @Accept  json
// @Produce  json
// @Success 200 {array} model.Tag
// @Failure 400 {object} httputil.HTTPError
// @Failure 404 {object} httputil.HTTPError
// @Failure 500 {object} httputil.HTTPError
// @Router /catalog/tags [get]
func (c *Controller) ListTags(ctx *gin.Context) {
	accounts, err := c.api.GetTags(ctx.Request.Context())
	if err != nil {
		httputil.NewError(ctx, http.StatusNotFound, err)
		return
	}
	ctx.JSON(http.StatusOK, accounts)
}

// CreateProductRequest es el cuerpo JSON de POST /catalog/products.
type CreateProductRequest struct {
	Name string `json:"name"`
}

// CreateProduct registra un producto y devuelve los "similares" por nombre.
//
// VULNERABLE A PROPÓSITO (POC WAF): el campo `name` del JSON se concatena en la consulta SQL
// (SQLi, ver repository.SearchProductsByName) y se refleja en la respuesta HTML sin escapar
// (XSS reflejado). Existe sólo para que el WAF tenga ataques reales que bloquear en la demo.
// @Router /catalog/products [post]
func (c *Controller) CreateProduct(ctx *gin.Context) {
	var req CreateProductRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		httputil.NewError(ctx, http.StatusBadRequest, err)
		return
	}

	products, err := c.api.SearchProductsByName(req.Name, ctx.Request.Context())
	if err != nil {
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	var sb strings.Builder
	sb.WriteString("<html><body>")
	sb.WriteString("<h1>Producto agregado: " + req.Name + "</h1>")
	sb.WriteString("<h2>Productos similares</h2><ul>")
	for _, p := range products {
		sb.WriteString("<li>" + p.Name + " ($" + strconv.Itoa(p.Price) + ")</li>")
	}
	sb.WriteString("</ul></body></html>")

	ctx.Data(http.StatusOK, "text/html; charset=utf-8", []byte(sb.String()))
}

func getQueryInt(name string, defaultValue int, ctx *gin.Context) (int, error) {
	str := ctx.Query(name)

	if len(str) > 0 {
		return strconv.Atoi(str)
	}

	return defaultValue, nil
}
