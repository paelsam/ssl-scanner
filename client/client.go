package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"sslscanner/model"
)

const (
	BaseURL        = "https://api.ssllabs.com/api/v2"
	DefaultTimeout = 30 * time.Second
)

type Client struct {
	httpClient *http.Client
	baseURL    string
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL: BaseURL,
	}
}

func NewClientWithTimeout(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL: BaseURL,
	}
}

func (c *Client) GetInfo(ctx context.Context) (*model.Info, error) {
	endpoint := fmt.Sprintf("%s/info", c.baseURL)

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("falló al obtener información del servicio: %w", err)
	}

	var info model.Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("falló al decodificar respuesta de info: %w", err)
	}

	return &info, nil
}

// StartAnalysis inicia un nuevo análisis con startNew=on
func (c *Client) StartAnalysis(ctx context.Context, domain string) (*model.Host, error) {
	params := url.Values{}
	params.Set("host", domain)
	params.Set("startNew", "on")
	params.Set("all", "done")

	endpoint := fmt.Sprintf("%s/analyze?%s", c.baseURL, params.Encode())

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("falló al iniciar análisis para %s: %w", domain, err)
	}

	var host model.Host
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, fmt.Errorf("falló al decodificar respuesta de análisis: %w", err)
	}

	return &host, nil
}

// CheckAnalysisStatus consulta el estado sin iniciar uno nuevo
func (c *Client) CheckAnalysisStatus(ctx context.Context, domain string) (*model.Host, error) {
	params := url.Values{}
	params.Set("host", domain)
	params.Set("all", "done")

	endpoint := fmt.Sprintf("%s/analyze?%s", c.baseURL, params.Encode())

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("falló al consultar estado del análisis para %s: %w", domain, err)
	}

	var host model.Host
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, fmt.Errorf("falló al decodificar respuesta de estado: %w", err)
	}

	return &host, nil
}

func (c *Client) GetEndpointDetails(ctx context.Context, domain, ipAddress string) (*model.Endpoint, error) {
	params := url.Values{}
	params.Set("host", domain)
	params.Set("s", ipAddress)

	endpoint := fmt.Sprintf("%s/getEndpointData?%s", c.baseURL, params.Encode())

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("falló al obtener detalles del endpoint %s: %w", ipAddress, err)
	}

	var ep model.Endpoint
	if err := json.Unmarshal(body, &ep); err != nil {
		return nil, fmt.Errorf("falló al decodificar detalles del endpoint: %w", err)
	}

	return &ep, nil
}

func (c *Client) doRequest(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("falló al crear solicitud HTTP: %w", err)
	}

	req.Header.Set("User-Agent", "sslscanner/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("falló la solicitud HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("falló al leer cuerpo de respuesta: %w", err)
	}

	if err := c.checkHTTPStatus(resp.StatusCode, body); err != nil {
		return nil, err
	}

	return body, nil
}

func (c *Client) checkHTTPStatus(statusCode int, body []byte) error {
	switch statusCode {
	case http.StatusOK:
		return nil
	case http.StatusBadRequest:
		var apiErr model.APIError
		if err := json.Unmarshal(body, &apiErr); err == nil && len(apiErr.Errors) > 0 {
			return fmt.Errorf("error de invocación (400): %s - %s", apiErr.Errors[0].Field, apiErr.Errors[0].Message)
		}
		return fmt.Errorf("error de invocación (400): parámetros inválidos")
	case http.StatusTooManyRequests:
		return fmt.Errorf("límite de tasa excedido (429): demasiadas solicitudes, espere antes de reintentar")
	case http.StatusInternalServerError:
		return fmt.Errorf("error interno del servidor (500): problema en SSL Labs")
	case http.StatusServiceUnavailable:
		return fmt.Errorf("servicio no disponible (503): SSL Labs en mantenimiento")
	case 529:
		return fmt.Errorf("servicio sobrecargado (529): SSL Labs está sobrecargado, intente más tarde")
	default:
		return fmt.Errorf("código de estado HTTP inesperado: %d", statusCode)
	}
}
