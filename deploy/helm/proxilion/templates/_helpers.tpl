{{/*
Common template helpers.
*/}}

{{- define "proxilion.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "proxilion.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{ printf "%s-%s" .Release.Name (include "proxilion.name" .) | trunc 63 | trimSuffix "-" }}
{{- end -}}
{{- end -}}

{{- define "proxilion.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "proxilion.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "proxilion.selectorLabels" -}}
app.kubernetes.io/name: {{ include "proxilion.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "proxilion.proxy.fullname" -}}
{{- printf "%s-proxy" (include "proxilion.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "proxilion.trustPlane.fullname" -}}
{{- printf "%s-trust-plane" (include "proxilion.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "proxilion.nats.fullname" -}}
{{- printf "%s-nats" (include "proxilion.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "proxilion.secretsName" -}}
{{- if .Values.secrets.existingSecret -}}
{{ .Values.secrets.existingSecret }}
{{- else -}}
{{ include "proxilion.fullname" . }}-secrets
{{- end -}}
{{- end -}}

{{- define "proxilion.policyConfigMapName" -}}
{{- if .Values.policy.existingConfigMap -}}
{{ .Values.policy.existingConfigMap }}
{{- else -}}
{{ include "proxilion.fullname" . }}-policy
{{- end -}}
{{- end -}}

{{- define "proxilion.natsUrl" -}}
{{- if .Values.proxy.env.nats.url -}}
{{ .Values.proxy.env.nats.url }}
{{- else -}}
nats://{{ include "proxilion.nats.fullname" . }}:{{ .Values.nats.service.clientPort }}
{{- end -}}
{{- end -}}
