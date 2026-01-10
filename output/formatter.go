package output

import (
	"fmt"
	"strings"
	"time"

	"sslscanner/model"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorBold   = "\033[1m"
)

type Formatter struct {
	useColors bool
}

func NewFormatter(useColors bool) *Formatter {
	return &Formatter{
		useColors: useColors,
	}
}

// PrintReport imprime el reporte completo de todos los endpoints
func (f *Formatter) PrintReport(host *model.Host) {
	f.printHeader(host)

	for i, endpoint := range host.Endpoints {
		f.printEndpointSummary(endpoint, i+1)

		// si el endpoint no completó el análisis, mostrar el error
		if endpoint.StatusMessage != "Ready" {
			f.printEndpointError(endpoint)
			fmt.Println(f.separator())
			continue
		}

		if endpoint.Details != nil {
			f.printProtocols(endpoint.Details.Protocols)
			f.printCipherSuites(endpoint.Details.Suites)
			f.printVulnerabilities(endpoint.Details)
			f.printCertificateInfo(endpoint.Details.Cert)
		}

		fmt.Println(f.separator())
	}
}

func (f *Formatter) printEndpointError(endpoint model.Endpoint) {
	fmt.Printf("\n%sEstado: %s%s\n", ColorRed, endpoint.StatusMessage, ColorReset)
	if endpoint.StatusDetailsMessage != "" {
		fmt.Printf("Detalle: %s\n", endpoint.StatusDetailsMessage)
	}
}

func (f *Formatter) printHeader(host *model.Host) {
	fmt.Println(f.separator())
	fmt.Printf("%s REPORTE DE ANÁLISIS TLS - SSL Labs %s\n", f.bold(""), f.reset())
	fmt.Println(f.separator())
	fmt.Printf("Dominio: %s\n", f.colorize(host.Host, ColorBlue))
	fmt.Printf("Puerto: %d\n", host.Port)
	fmt.Printf("Protocolo: %s\n", host.Protocol)

	if host.TestTime > 0 {
		testTime := time.UnixMilli(host.TestTime)
		fmt.Printf("Fecha del análisis: %s\n", testTime.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("Motor SSL Labs: %s\n", host.EngineVersion)
	fmt.Printf("Criterios de evaluación: %s\n", host.CriteriaVersion)
	fmt.Println(f.separator())
}

func (f *Formatter) printEndpointSummary(endpoint model.Endpoint, index int) {
	fmt.Printf("\n%s ENDPOINT #%d %s\n", f.bold(""), index, f.reset())
	fmt.Printf("IP: %s\n", endpoint.IPAddress)

	if endpoint.ServerName != "" {
		fmt.Printf("Nombre del servidor: %s\n", endpoint.ServerName)
	}

	gradeColor := f.getGradeColor(endpoint.Grade)
	fmt.Printf("Calificación: %s\n", f.colorize(endpoint.Grade, gradeColor))

	if endpoint.GradeTrustIgnored != "" && endpoint.GradeTrustIgnored != endpoint.Grade {
		fmt.Printf("Calificación (ignorando confianza): %s\n", endpoint.GradeTrustIgnored)
	}

	if endpoint.HasWarnings {
		fmt.Printf("%s⚠ Este endpoint tiene advertencias que pueden afectar la calificación%s\n",
			ColorYellow, ColorReset)
	}

	if endpoint.IsExceptional {
		fmt.Printf("%s★ Configuración excepcional detectada%s\n", ColorGreen, ColorReset)
	}

	fmt.Printf("Duración del análisis: %dms\n", endpoint.Duration)
}

func (f *Formatter) printProtocols(protocols []model.Protocol) {
	fmt.Printf("\n%s Protocolos Soportados %s\n", f.bold(""), f.reset())

	if len(protocols) == 0 {
		fmt.Println("  No se encontraron protocolos.")
		return
	}

	for _, proto := range protocols {
		status := f.getProtocolStatus(proto)
		fmt.Printf("  • %s %s: %s\n", proto.Name, proto.Version, status)
	}
}

func (f *Formatter) getProtocolStatus(proto model.Protocol) string {
	// Los protocolos con Q=0 son inseguros
	if proto.Q != nil && *proto.Q == 0 {
		return f.colorize("INSEGURO", ColorRed)
	}

	// SSLv2 y SSLv3 siempre son inseguros
	if proto.Name == "SSL" {
		return f.colorize("INSEGURO (obsoleto)", ColorRed)
	}

	// TLS 1.0 y 1.1 están deprecados
	if proto.Name == "TLS" && (proto.Version == "1.0" || proto.Version == "1.1") {
		return f.colorize("DEPRECADO", ColorYellow)
	}

	return f.colorize("OK", ColorGreen)
}

func (f *Formatter) printCipherSuites(suites *model.Suites) {
	fmt.Printf("\n%s Cipher Suites %s\n", f.bold(""), f.reset())

	if suites == nil || len(suites.List) == 0 {
		fmt.Println("  No se encontraron cipher suites.")
		return
	}

	if suites.Preference {
		fmt.Println("  El servidor selecciona activamente las cipher suites.")
	}

	weakSuites := []string{}
	strongSuites := []string{}

	for _, suite := range suites.List {
		// Las suites con Q=0 son débiles
		if suite.Q != nil && *suite.Q == 0 {
			weakSuites = append(weakSuites, fmt.Sprintf("%s (fuerza: %d bits)",
				suite.Name, suite.CipherStrength))
		} else if suite.CipherStrength >= 128 {
			strongSuites = append(strongSuites, fmt.Sprintf("%s (fuerza: %d bits)",
				suite.Name, suite.CipherStrength))
		}
	}

	fmt.Printf("  Total de suites: %d\n", len(suites.List))

	if len(weakSuites) > 0 {
		fmt.Printf("\n  %sCifrados Débiles Detectados:%s\n", ColorRed, ColorReset)
		for _, suite := range weakSuites {
			fmt.Printf("    ✗ %s\n", suite)
		}
	}

	// Mostrar solo las primeras 5 suites fuertes para no saturar la salida
	if len(strongSuites) > 0 {
		fmt.Printf("\n  Cifrados Fuertes (mostrando hasta 5):\n")
		limit := 5
		if len(strongSuites) < limit {
			limit = len(strongSuites)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("    ✓ %s\n", strongSuites[i])
		}
		if len(strongSuites) > 5 {
			fmt.Printf("    ... y %d más\n", len(strongSuites)-5)
		}
	}
}

// printVulnerabilities muestra heartbleed, poodle, beast, freak, logjam, rc4
func (f *Formatter) printVulnerabilities(details *model.EndpointDetails) {
	fmt.Printf("\n%s Vulnerabilidades Conocidas %s\n", f.bold(""), f.reset())

	vulnerabilities := []struct {
		name       string
		vulnerable bool
		severity   string
	}{
		{"Heartbleed (CVE-2014-0160)", details.Heartbleed, "CRÍTICA"},
		{"POODLE (SSLv3)", details.Poodle, "ALTA"},
		{"BEAST", details.VulnBeast, "MEDIA"},
		{"FREAK", details.Freak, "ALTA"},
		{"Logjam", details.Logjam, "ALTA"},
		{"Soporta RC4", details.SupportsRC4, "MEDIA"},
	}

	foundVulnerabilities := false
	for _, vuln := range vulnerabilities {
		if vuln.vulnerable {
			foundVulnerabilities = true
			fmt.Printf("  %s✗ %s - Severidad: %s%s\n",
				ColorRed, vuln.name, vuln.severity, ColorReset)
		}
	}

	// Verificar OpenSSL CCS (CVE-2014-0224)
	if details.OpenSSLCcs >= 2 {
		foundVulnerabilities = true
		fmt.Printf("  %s✗ OpenSSL CCS (CVE-2014-0224) - Severidad: CRÍTICA%s\n",
			ColorRed, ColorReset)
	}

	// Verificar POODLE TLS
	if details.PoodleTLS == 2 {
		foundVulnerabilities = true
		fmt.Printf("  %s✗ POODLE TLS - Severidad: ALTA%s\n", ColorRed, ColorReset)
	}

	if !foundVulnerabilities {
		fmt.Printf("  %s✓ No se detectaron vulnerabilidades conocidas%s\n",
			ColorGreen, ColorReset)
	}

	// Información adicional de seguridad
	fmt.Printf("\n%s Características de Seguridad %s\n", f.bold(""), f.reset())

	// Forward Secrecy
	fsStatus := "No soportado"
	if details.ForwardSecrecy >= 4 {
		fsStatus = f.colorize("Completo (todos los clientes)", ColorGreen)
	} else if details.ForwardSecrecy >= 2 {
		fsStatus = f.colorize("Parcial (clientes modernos)", ColorYellow)
	} else if details.ForwardSecrecy >= 1 {
		fsStatus = f.colorize("Limitado", ColorYellow)
	}
	fmt.Printf("  Forward Secrecy: %s\n", fsStatus)

	// HSTS
	if details.HstsPolicy != nil {
		hstsStatus := "No configurado"
		if details.HstsPolicy.Status == "present" {
			hstsStatus = f.colorize("Habilitado", ColorGreen)
			if details.HstsPolicy.Preload {
				hstsStatus += " (con preload)"
			}
		}
		fmt.Printf("  HSTS: %s\n", hstsStatus)
	}

	// OCSP Stapling
	ocspStatus := f.colorize("No", ColorYellow)
	if details.OcspStapling {
		ocspStatus = f.colorize("Sí", ColorGreen)
	}
	fmt.Printf("  OCSP Stapling: %s\n", ocspStatus)

	// TLS Fallback SCSV
	if details.FallbackScsv {
		fmt.Printf("  TLS Fallback SCSV: %s\n", f.colorize("Soportado", ColorGreen))
	}
}

func (f *Formatter) printCertificateInfo(cert *model.Cert) {
	if cert == nil {
		return
	}

	// verificar si hay datos útiles
	if cert.Subject == "" && cert.IssuerLabel == "" && cert.SigAlg == "" {
		return
	}

	fmt.Printf("\n%s Información del Certificado %s\n", f.bold(""), f.reset())

	if cert.Subject != "" {
		fmt.Printf("  Sujeto: %s\n", cert.Subject)
	}
	if cert.IssuerLabel != "" {
		fmt.Printf("  Emisor: %s\n", cert.IssuerLabel)
	}
	if cert.SigAlg != "" {
		fmt.Printf("  Algoritmo de firma: %s\n", cert.SigAlg)
	}

	if cert.NotBefore > 0 {
		notBefore := time.UnixMilli(cert.NotBefore)
		fmt.Printf("  Válido desde: %s\n", notBefore.Format("2006-01-02"))
	}

	if cert.NotAfter > 0 {
		notAfter := time.UnixMilli(cert.NotAfter)
		fmt.Printf("  Válido hasta: %s\n", notAfter.Format("2006-01-02"))

		daysRemaining := int(time.Until(notAfter).Hours() / 24)
		if daysRemaining < 0 {
			fmt.Printf("  %s⚠ CERTIFICADO EXPIRADO%s\n", ColorRed, ColorReset)
		} else if daysRemaining < 30 {
			fmt.Printf("  %s⚠ El certificado expira en %d días%s\n",
				ColorYellow, daysRemaining, ColorReset)
		}
	}

	if len(cert.AltNames) > 0 {
		fmt.Printf("  Nombres alternativos: %s\n", strings.Join(cert.AltNames[:min(5, len(cert.AltNames))], ", "))
		if len(cert.AltNames) > 5 {
			fmt.Printf("    ... y %d más\n", len(cert.AltNames)-5)
		}
	}

	// Verificar problemas del certificado
	if cert.Issues > 0 {
		fmt.Printf("\n  %sProblemas detectados en el certificado:%s\n", ColorRed, ColorReset)
		f.printCertIssues(cert.Issues)
	}
}

func (f *Formatter) printCertIssues(issues int) {
	issueMap := map[int]string{
		1:   "Sin cadena de confianza",
		2:   "Certificado aún no válido",
		4:   "Certificado expirado",
		8:   "Nombre de host no coincide",
		16:  "Certificado revocado",
		32:  "Common name incorrecto",
		64:  "Certificado autofirmado",
		128: "Certificado en lista negra",
		256: "Firma insegura",
	}

	for bit, desc := range issueMap {
		if issues&bit != 0 {
			fmt.Printf("    ✗ %s\n", desc)
		}
	}
}

func (f *Formatter) getGradeColor(grade string) string {
	switch {
	case strings.HasPrefix(grade, "A"):
		return ColorGreen
	case strings.HasPrefix(grade, "B"):
		return ColorYellow
	case grade == "T" || grade == "M":
		return ColorRed
	default:
		return ColorRed
	}
}

func (f *Formatter) colorize(text, color string) string {
	if !f.useColors {
		return text
	}
	return color + text + ColorReset
}

func (f *Formatter) bold(text string) string {
	if !f.useColors {
		return text
	}
	return ColorBold + text
}

func (f *Formatter) reset() string {
	if !f.useColors {
		return ""
	}
	return ColorReset
}

func (f *Formatter) separator() string {
	return strings.Repeat("═", 60)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
