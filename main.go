/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

// All code below is based from ingress-nginx annotation parser.
// https://github.com/kubernetes/ingress-nginx
// The code can be used to parse annotations from ingress-nginx

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// https://github.com/kubernetes/ingress-nginx/blob/main/internal/ingress/annotations/parser/main.go#L62
// get all annotation fields from ingress-nginx

type AnnotationValidator func(string) error

const (
	AnnotationRiskLow AnnotationRisk = iota
	AnnotationRiskMedium
	AnnotationRiskHigh
	AnnotationRiskCritical
)

var (
	alphaNumericChars    = `\-\.\_\~a-zA-Z0-9\/:`
	extendedAlphaNumeric = alphaNumericChars + ", "
	regexEnabledChars    = regexp.QuoteMeta(`^$[](){}*+?|&=\`)
	urlEnabledChars      = regexp.QuoteMeta(`:?&=`)
)

// IsValidRegex checks if the tested string can be used as a regex, but without any weird character.
// It includes regex characters for paths that may contain regexes
var IsValidRegex = regexp.MustCompile("^[/" + alphaNumericChars + regexEnabledChars + "]*$")

// SizeRegex validates sizes understood by NGINX, like 1000, 100k, 1000M
var SizeRegex = regexp.MustCompile(`^(?i)\d+[bkmg]?$`)

// URLRegex is used to validate a URL but with only a specific set of characters:
// It is alphanumericChar + ":", "?", "&"
// A valid URL would be proto://something.com:port/something?arg=param
var (
	// URLIsValidRegex is used on full URLs, containing query strings (:, ? and &)
	URLIsValidRegex = regexp.MustCompile("^[" + alphaNumericChars + urlEnabledChars + "]*$")
	// BasicChars is alphanumeric and ".", "-", "_", "~" and ":", usually used on simple host:port/path composition.
	// This combination can also be used on fields that may contain characters like / (as ns/name)
	BasicCharsRegex = regexp.MustCompile("^[/" + alphaNumericChars + "]*$")
	// ExtendedChars is alphanumeric and ".", "-", "_", "~" and ":" plus "," and spaces, usually used on simple host:port/path composition
	ExtendedCharsRegex = regexp.MustCompile("^[/" + extendedAlphaNumeric + "]*$")
	// CharsWithSpace is like basic chars, but includes the space character
	CharsWithSpace = regexp.MustCompile("^[/" + alphaNumericChars + " ]*$")
	// NGINXVariable allows entries with alphanumeric characters, -, _ and the special "$"
	NGINXVariable = regexp.MustCompile(`^[A-Za-z0-9\-\_\$\{\}]*$`)
	// RegexPathWithCapture allows entries that SHOULD start with "/" and may contain alphanumeric + capture
	// character for regex based paths, like /something/$1/anything/$2
	RegexPathWithCapture = regexp.MustCompile(`^/[` + alphaNumericChars + `\/\$]*$`)
	// HeadersVariable defines a regex that allows headers separated by comma
	HeadersVariable = regexp.MustCompile(`^[A-Za-z0-9-_, ]*$`)
	// URLWithNginxVariableRegex defines a url that can contain nginx variables.
	// It is a risky operation
	URLWithNginxVariableRegex = regexp.MustCompile("^[" + alphaNumericChars + urlEnabledChars + "$]*$")
)

// IPNet maps string to net.IPNet.
type IPNet map[string]*net.IPNet

// IP maps string to net.IP.
type IP map[string]net.IP

// ParseIPNets parses string slice to IPNet.
func ParseIPNets(specs ...string) (IPNet, IP, error) {
	ipnetset := make(IPNet)
	ipset := make(IP)

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		_, ipnet, err := net.ParseCIDR(spec)
		if err != nil {
			ip := net.ParseIP(spec)
			if ip == nil {
				return nil, nil, err
			}
			i := ip.String()
			ipset[i] = ip
			continue
		}

		k := ipnet.String()
		ipnetset[k] = ipnet
	}

	return ipnetset, ipset, nil
}

// ParseCIDRs parses comma separated CIDRs into a sorted string array
func ParseCIDRs(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}

	values := strings.Split(s, ",")

	ipnets, ips, err := ParseIPNets(values...)
	if err != nil {
		return nil, err
	}

	cidrs := []string{}
	for k := range ipnets {
		cidrs = append(cidrs, k)
	}

	for k := range ips {
		cidrs = append(cidrs, k)
	}

	sort.Strings(cidrs)

	return cidrs, nil
}

// ValidateArrayOfServerName validates if all fields on a Server name annotation are
// regexes. They can be *.something*, ~^www\d+\.example\.com$ but not fancy character
func ValidateArrayOfServerName(value string) error {
	for _, fqdn := range strings.Split(value, ",") {
		if err := ValidateServerName(fqdn); err != nil {
			return err
		}
	}
	return nil
}

// ValidateServerName validates if the passed value is an acceptable server name. The server name
// can contain regex characters, as those are accepted values on nginx configuration
func ValidateServerName(value string) error {
	value = strings.TrimSpace(value)
	if !IsValidRegex.MatchString(value) {
		return fmt.Errorf("value %s is invalid server name", value)
	}
	return nil
}

// ValidateRegex receives a regex as an argument and uses it to validate
// the value of the field.
// Annotation can define if the spaces should be trimmed before validating the value
func ValidateRegex(regex *regexp.Regexp, removeSpace bool) AnnotationValidator {
	return func(s string) error {
		if removeSpace {
			s = strings.ReplaceAll(s, " ", "")
		}
		if !regex.MatchString(s) {
			return fmt.Errorf("value %s is invalid", s)
		}
		return nil
	}
}

// ValidateOptions receives an array of valid options that can be the value of annotation.
// If no valid option is found, it will return an error
func ValidateOptions(options []string, caseSensitive, trimSpace bool) AnnotationValidator {
	return func(s string) error {
		if trimSpace {
			s = strings.TrimSpace(s)
		}
		if !caseSensitive {
			s = strings.ToLower(s)
		}
		for _, option := range options {
			if s == option {
				return nil
			}
		}
		return fmt.Errorf("value does not match any valid option")
	}
}

// ValidateBool validates if the specified value is a bool
func ValidateBool(value string) error {
	_, err := strconv.ParseBool(value)
	return err
}

// ValidateInt validates if the specified value is an integer
func ValidateInt(value string) error {
	_, err := strconv.Atoi(value)
	return err
}

// ValidateCIDRs validates if the specified value is an array of IPs and CIDRs
func ValidateCIDRs(value string) error {
	_, err := ParseCIDRs(value)
	return err
}

// ValidateDuration validates if the specified value is a valid time
func ValidateDuration(value string) error {
	_, err := time.ParseDuration(value)
	return err
}

// ValidateNull always return null values and should not be widely used.
// It is used on the "snippet" annotations, as it is up to the admin to allow its
// usage, knowing it can be critical!
func ValidateNull(_ string) error {
	return nil
}

// checkAnnotations will check each annotation for:
// 1 - Does it contain the internal validation and docs config?
// 2 - Does the ingress contains annotations? (validate null pointers)
// 3 - Does it contains a validator? Should it contain a validator (not containing is a bug!)
// 4 - Does the annotation contain aliases? So we should use if the alias is defined an the annotation not.
// 4 - Runs the validator on the value
// It will return the full annotation name if all is fine
func checkAnnotation(name string, ing *networking.Ingress, fields AnnotationFields) (string, error) {
	var validateFunc AnnotationValidator
	if fields != nil {
		config, ok := fields[name]
		if !ok {
			return "", fmt.Errorf("annotation does not contain a valid internal configuration, this is an Ingress Controller issue! Please raise an issue on github.com/kubernetes/ingress-nginx")
		}
		validateFunc = config.Validator
	}

	if ing == nil || len(ing.GetAnnotations()) == 0 {
		return "", errors.New("ErrMissingAnnotations")
	}

	annotationFullName := GetAnnotationWithPrefix(name)
	if annotationFullName == "" {
		return "", errors.New("ErrInvalidAnnotationName")
	}

	annotationValue := ing.GetAnnotations()[annotationFullName]
	if fields != nil {
		if validateFunc == nil {
			return "", fmt.Errorf("annotation does not contain a validator. This is an ingress-controller bug. Please open an issue")
		}
		if annotationValue == "" {
			for _, annotationAlias := range fields[name].AnnotationAliases {
				tempAnnotationFullName := GetAnnotationWithPrefix(annotationAlias)
				if aliasVal := ing.GetAnnotations()[tempAnnotationFullName]; aliasVal != "" {
					annotationValue = aliasVal
					annotationFullName = tempAnnotationFullName
					break
				}
			}
		}
		// We don't run validation against empty values
		if EnableAnnotationValidation && annotationValue != "" {
			if err := validateFunc(annotationValue); err != nil {
				log.Printf("validation error on ingress %s/%s: annotation %s contains invalid value %s", ing.GetNamespace(), ing.GetName(), name, annotationValue)
				return "", errors.New("NewValidationError(Annotationfullname)")
			}
		}
	}

	return annotationFullName, nil
}

// DefaultAnnotationsPrefix defines the common prefix used in the nginx ingress controller
const (
	DefaultAnnotationsPrefix          = "nginx.ingress.kubernetes.io"
	DefaultEnableAnnotationValidation = true
)

var (
	// AnnotationsPrefix is the mutable attribute that the controller explicitly refers to
	AnnotationsPrefix = DefaultAnnotationsPrefix
	// Enable is the mutable attribute for enabling or disabling the validation functions
	EnableAnnotationValidation = DefaultEnableAnnotationValidation
)

// AnnotationGroup defines the group that this annotation may belong
// eg.: Security, Snippets, Rewrite, etc
type AnnotationGroup string

// AnnotationScope defines which scope this annotation applies. May be to the whole
// ingress, per location, etc
type AnnotationScope string

var (
	AnnotationScopeLocation AnnotationScope = "location"
	AnnotationScopeIngress  AnnotationScope = "ingress"
)

// AnnotationRisk is a subset of risk that an annotation may represent.
// Based on the Risk, the admin will be able to allow or disallow users to set it
// on their ingress objects
type AnnotationRisk int

type AnnotationFields map[string]AnnotationConfig

// AnnotationConfig defines the configuration that a single annotation field
// has, with the Validator and the documentation of this field.
type AnnotationConfig struct {
	// Validator defines a function to validate the annotation value
	Validator AnnotationValidator
	// Documentation defines a user facing documentation for this annotation. This
	// field will be used to auto generate documentations
	Documentation string
	// Risk defines a risk of this annotation being exposed to the user. Annotations
	// with bool fields, or to set timeout are usually low risk. Annotations that allows
	// string input without a limited set of options may represent a high risk
	Risk AnnotationRisk

	// Scope defines which scope this annotation applies, may be to location, to an Ingress object, etc
	Scope AnnotationScope

	// AnnotationAliases defines other names this annotation may have.
	AnnotationAliases []string
}

// Annotation defines an annotation feature an Ingress may have.
// It should contain the internal resolver, and all the annotations
// with configs and Validators that should be used for each Annotation
type Annotation struct {
	// Annotations contains all the annotations that belong to this feature
	Annotations AnnotationFields
	// Group defines which annotation group this feature belongs to
	Group AnnotationGroup
}

// GetAnnotationWithPrefix returns the prefix of ingress annotations
func GetAnnotationWithPrefix(suffix string) string {
	return fmt.Sprintf("%v/%v", AnnotationsPrefix, suffix)
}

func TrimAnnotationPrefix(annotation string) string {
	return strings.TrimPrefix(annotation, AnnotationsPrefix+"/")
}

func StringRiskToRisk(risk string) AnnotationRisk {
	switch strings.ToLower(risk) {
	case "critical":
		return AnnotationRiskCritical
	case "high":
		return AnnotationRiskHigh
	case "medium":
		return AnnotationRiskMedium
	default:
		return AnnotationRiskLow
	}
}

const (
	fromToWWWRedirAnnotation        = "from-to-www-redirect"
	temporalRedirectAnnotation      = "temporal-redirect"
	permanentRedirectAnnotation     = "permanent-redirect"
	permanentRedirectAnnotationCode = "permanent-redirect-code"
)

// nginx.ingress.kubernetes.io/permanent-redirect: https://rocketeerbkw.com$request_uri

func main() {
	parseServerSnippets := false
	parseRedirects := true
	flag.BoolVar(&parseServerSnippets, "parse-server-snippets", false, "Parse server-snippet annotations")
	flag.BoolVar(&parseRedirects, "parse-redirects", true, "Parse redirect annotations")

	kubeconfig := os.Getenv("KUBECONFIG")
	ctx := context.Background()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("error building kubeconfig: %s", err)
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("could not create clientset: %s", err)
	}

	// NOTE that server snippets are not validated at all, so it's usage is not recommended
	serversnippets := AnnotationFields{
		"server-snippet": {
			Validator:     ValidateNull,
			Scope:         AnnotationScopeIngress,
			Risk:          AnnotationRiskCritical, // Critical, this annotation is not validated at all and allows arbitrary configutations
			Documentation: `This annotation allows setting a custom NGINX configuration on a server block. This annotation does not contain any validation and it's usage is not recommended!`,
		},
	}

	redirects := AnnotationFields{
		fromToWWWRedirAnnotation: {
			Validator:     ValidateBool,
			Scope:         AnnotationScopeLocation,
			Risk:          AnnotationRiskLow, // Low, as it allows just a set of options
			Documentation: `In some scenarios is required to redirect from www.domain.com to domain.com or vice versa. To enable this feature use this annotation.`,
		},
		temporalRedirectAnnotation: {
			Validator: ValidateRegex(URLIsValidRegex, false),
			Scope:     AnnotationScopeLocation,
			Risk:      AnnotationRiskMedium, // Medium, as it allows arbitrary URLs that needs to be validated
			Documentation: `This annotation allows you to return a temporal redirect (Return Code 302) instead of sending data to the upstream.
			For example setting this annotation to https://www.google.com would redirect everything to Google with a Return Code of 302 (Moved Temporarily).`,
		},
		permanentRedirectAnnotation: {
			Validator: ValidateRegex(URLIsValidRegex, false),
			Scope:     AnnotationScopeLocation,
			Risk:      AnnotationRiskMedium, // Medium, as it allows arbitrary URLs that needs to be validated
			Documentation: `This annotation allows to return a permanent redirect (Return Code 301) instead of sending data to the upstream.
			For example setting this annotation https://www.google.com would redirect everything to Google with a code 301`,
		},
		permanentRedirectAnnotationCode: {
			Validator:     ValidateInt,
			Scope:         AnnotationScopeLocation,
			Risk:          AnnotationRiskLow, // Low, as it allows just a set of options
			Documentation: `This annotation allows you to modify the status code used for permanent redirects.`,
		},
	}
	ings, err := clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Fatalf("error listing ingresses: %s", err)
	}

	for _, ing := range ings.Items {
		if parseServerSnippets {
			for k := range serversnippets {
				_, err := checkAnnotation(k, &ing, redirects)
				if err != nil {
					log.Printf("ingress: %s, namespace: %s, field: %s failed with: %s", ing.GetName(), ing.GetNamespace(), k, err)
				}
			}
		}

		if parseRedirects {
			for k := range redirects {
				_, err := checkAnnotation(k, &ing, redirects)
				if err != nil {
					log.Printf("ingress: %s, namespace: %s, field: %s failed with: %s", ing.GetName(), ing.GetNamespace(), k, err)
					continue
				}
			}
		}
	}
}
