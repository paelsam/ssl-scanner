package service

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"sslscanner/client"
	"sslscanner/model"
)

const (
	StatusDNS        = "DNS"
	StatusError      = "ERROR"
	StatusInProgress = "IN_PROGRESS"
	StatusReady      = "READY"

	PollIntervalInitial = 5 * time.Second
	PollIntervalRunning = 10 * time.Second
	MaxWaitTime         = 15 * time.Minute
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

type Scanner struct {
	client *client.Client
}

func NewScanner() *Scanner {
	return &Scanner{
		client: client.NewClient(),
	}
}

func NewScannerWithClient(c *client.Client) *Scanner {
	return &Scanner{
		client: c,
	}
}

func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("el dominio no puede estar vacío")
	}

	if len(domain) > 253 {
		return fmt.Errorf("el dominio excede la longitud máxima de 253 caracteres")
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("formato de dominio inválido: %s", domain)
	}

	return nil
}

// RunAnalysis ejecuta el flujo completo: validar, iniciar y esperar resultado
func (s *Scanner) RunAnalysis(ctx context.Context, domain string) (*model.Host, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("validación fallida: %w", err)
	}

	info, err := s.client.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("no se pudo verificar disponibilidad del servicio: %w", err)
	}

	if info.CurrentAssessments >= info.MaxAssessments {
		return nil, fmt.Errorf("límite de análisis concurrentes alcanzado (%d/%d)",
			info.CurrentAssessments, info.MaxAssessments)
	}

	host, err := s.client.StartAnalysis(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("no se pudo iniciar el análisis: %w", err)
	}

	if host.Status == StatusReady || host.Status == StatusError {
		return host, nil
	}

	// Verificar que la caché tenga los resultados antes de hacer polling (con CheckDomainInCache)
	cacheFilePath := fmt.Sprintf("cache/%s.json", domain)
	inCache, err := client.CheckDomainInCache(cacheFilePath, domain)
	if err != nil {
		return nil, fmt.Errorf("error al verificar caché: %w", err)
	}
	if inCache {
		host, err := client.LoadLocalCache(cacheFilePath, domain)
		if err == nil {
			return host, nil
		}
		// Si hay error al cargar la caché, continuar con el polling
	}



	return s.pollAnalysisStatus(ctx, domain)
}

// pollAnalysisStatus hace polling hasta que el análisis termine o falle
func (s *Scanner) pollAnalysisStatus(ctx context.Context, domain string) (*model.Host, error) {
	startTime := time.Now()
	pollInterval := PollIntervalInitial

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("análisis cancelado: %w", ctx.Err())
		case <-time.After(pollInterval):
		}

		if time.Since(startTime) > MaxWaitTime {
			return nil, fmt.Errorf("tiempo máximo de espera excedido (%v)", MaxWaitTime)
		}

		host, err := s.client.CheckAnalysisStatus(ctx, domain)

		// Guardad host en caché local cada vez que se obtiene un estado actualizado
		cacheFilePath := fmt.Sprintf("cache/%s.json", domain)
		if err == nil {
			saveErr := client.SaveToLocalCache(cacheFilePath, host)
			if saveErr != nil {
				fmt.Printf("Advertencia: no se pudo guardar en caché local: %v\n", saveErr)
			}
		}

		if err != nil {
			return nil, fmt.Errorf("error al consultar estado: %w", err)
		}

		switch host.Status {
		case StatusReady:
			

			return host, nil
		case StatusError:
			return nil, fmt.Errorf("el análisis terminó con error: %s", host.StatusMessage)
		case StatusInProgress:
			pollInterval = PollIntervalRunning
			s.reportProgress(host)
		case StatusDNS:
			pollInterval = PollIntervalInitial
		}
	}
}

func (s *Scanner) reportProgress(host *model.Host) {
	for _, endpoint := range host.Endpoints {
		if endpoint.Progress >= 0 {
			fmt.Printf("  [%s] Progreso: %d%% - %s\n",
				endpoint.IPAddress, endpoint.Progress, endpoint.StatusDetailsMessage)
		}
	}
}

func (s *Scanner) GetServiceInfo(ctx context.Context) (*model.Info, error) {
	return s.client.GetInfo(ctx)
}
