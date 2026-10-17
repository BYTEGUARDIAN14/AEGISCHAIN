package main

import (
	"encoding/json"
	"time"
)

// AdmissionReview encapsulates the v1 admission review payload from Kubernetes.
type AdmissionReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Request    *AdmissionRequest `json:"request,omitempty"`
	Response   *AdmissionResponse`json:"response,omitempty"`
}

// AdmissionRequest contains information about the intercepted resource.
type AdmissionRequest struct {
	UID       string          `json:"uid"`
	Kind      GroupVersionKind`json:"kind"`
	Resource  GroupVersionResource `json:"resource"`
	Namespace string          `json:"namespace"`
	Operation string          `json:"operation"`
	UserInfo  UserInfo        `json:"userInfo"`
	Object    json.RawMessage `json:"object"`
	DryRun    bool            `json:"dryRun"`
}

// GroupVersionKind identifies the kind of resource.
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// GroupVersionResource identifies the resource.
type GroupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// UserInfo represents the identity making the Kubernetes API request.
type UserInfo struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

// AdmissionResponse contains the admission decision.
type AdmissionResponse struct {
	UID       string        `json:"uid"`
	Allowed   bool          `json:"allowed"`
	Status    *StatusResult `json:"status,omitempty"`
	Warnings  []string      `json:"warnings,omitempty"`
	PatchType string        `json:"patchType,omitempty"`
	Patch     []byte        `json:"patch,omitempty"`
}

// StatusResult provides human-readable context when a request is denied.
type StatusResult struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// ContainerSpec holds container name and image reference.
type ContainerSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// PodSpec holds container definitions for analysis.
type PodSpec struct {
	Containers          []ContainerSpec `json:"containers"`
	InitContainers      []ContainerSpec `json:"initContainers,omitempty"`
	EphemeralContainers []ContainerSpec `json:"ephemeralContainers,omitempty"`
	HostNetwork         bool            `json:"hostNetwork,omitempty"`
}

// PodObject models the Kubernetes Pod resource metadata and spec.
type PodObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
		Labels      map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec PodSpec `json:"spec"`
}

// WorkloadTemplateObject models Deployments, StatefulSets, DaemonSets, and Jobs.
type WorkloadTemplateObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec PodSpec `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

// CronJobObject models Kubernetes CronJob resources.
type CronJobObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		JobTemplate struct {
			Spec struct {
				Template struct {
					Metadata struct {
						Annotations map[string]string `json:"annotations"`
					} `json:"metadata"`
					Spec PodSpec `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

// JSONPatchOperation models standard RFC 6902 JSON patch operations for mutation.
type JSONPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// BreakGlassMetadata holds parsed emergency break-glass credentials.
type BreakGlassMetadata struct {
	Invoked   bool
	Token     string
	Reason    string
	Approver  string
	ExpiresAt time.Time
}
