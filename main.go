package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"sslscanner/output"
	"sslscanner/service"
)

const (
	exitCodeSuccess       = 0
	exitCodeInvalidArgs   = 1
	exitCodeAnalysisError = 2
)

func main() {
	os.Exit(run())
}

func run() int {
	noColor := flag.Bool("no-color", false, "Deshabilitar colores en la salida")
	showInfo := flag.Bool("info", false, "Mostrar información del servicio SSL Labs")
	flag.Usage = printUsage
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandler(cancel)

	scanner := service.NewScanner()
	formatter := output.NewFormatter(!*noColor)

	if *showInfo {
		return showServiceInfo(ctx, scanner)
	}

	args := flag.Args()
	if len(args) != 1 {
		printUsage()
		return exitCodeInvalidArgs
	}

	domain := args[0]

	fmt.Printf("Iniciando análisis TLS para: %s\n", domain)
	fmt.Println("Este proceso puede demorar...")
	fmt.Println()

	result, err := scanner.RunAnalysis(ctx, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitCodeAnalysisError
	}

	formatter.PrintReport(result)

	return exitCodeSuccess
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `SSL Labs TLS Scanner

Uso:
  sslscanner [opciones] <dominio>

Descripción:
  Analiza la configuración TLS/SSL de un dominio usando la API de SSL Labs.
  El análisis incluye calificación, protocolos, cifrados y vulnerabilidades.

Opciones:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Ejemplos:
  sslscanner example.com
  sslscanner --no-color example.com
  sslscanner --info
`)
}

func setupSignalHandler(cancel context.CancelFunc) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		fmt.Println("\nRecibida señal de interrupción, cancelando análisis...")
		cancel()
	}()
}

func showServiceInfo(ctx context.Context, scanner *service.Scanner) int {
	info, err := scanner.GetServiceInfo(ctx)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al obtener información del servicio: %v\n", err)
		return exitCodeAnalysisError
	}

	fmt.Println("Información del Servicio SSL Labs")
	fmt.Printf("Versión del motor: %s\n", info.Version)
	fmt.Printf("Versión de criterios: %s\n", info.CriteriaVersion)
	fmt.Printf("Análisis máximos concurrentes: %d\n", info.MaxAssessments)
	fmt.Printf("Análisis actuales: %d\n", info.CurrentAssessments)
	fmt.Printf("Período de espera entre análisis: %dms\n", info.NewAssessmentCoolOff)

	if len(info.Messages) > 0 {
		fmt.Println("\nMensajes del servicio:")
		for _, msg := range info.Messages {
			fmt.Printf("  • %s\n", msg)
		}
	}

	return exitCodeSuccess
}
