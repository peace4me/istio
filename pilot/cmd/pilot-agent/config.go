// Copyright 2020 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	networking "istio.io/api/networking/v1alpha3"

	"istio.io/api/annotation"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/pkg/log"

	"istio.io/istio/pilot/pkg/proxy"
	"istio.io/istio/pilot/pkg/serviceregistry"
	"istio.io/istio/pkg/bootstrap"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/validation"
)

// getTLSCerts returns all file based certificates from mesh config
// TODO(https://github.com/istio/istio/issues/21834) serve over SDS instead of files
// This is used for static configuration in the bootstrap that needs certificates, currently this is
// Envoy Metrics Service and ALS. In the future this could expand to others like tracing, which currently
// are using other mechanisms to configure certs.
// 获取所有基于文件的tls证书
// 当前只适用于Envoy度量服务或者ALS
// 后续将会扩展到其他服务比如追踪(目前通过其他的机制来配置证书)等。
func getTLSCerts(pc meshconfig.ProxyConfig) []string {
	certs := []string{}
	appendTLSCerts := func(rs *meshconfig.RemoteService) {
		if rs.TlsSettings == nil {
			return
		}
		if rs.TlsSettings.Mode == networking.ClientTLSSettings_DISABLE {
			return
		}
		//append only if the elements are not null.
		if rs.TlsSettings.CaCertificates != "" {
			certs = append(certs, rs.TlsSettings.CaCertificates)
		}
		if rs.TlsSettings.ClientCertificate != "" {
			certs = append(certs, rs.TlsSettings.ClientCertificate)
		}
		if rs.TlsSettings.PrivateKey != "" {
			certs = append(certs, rs.TlsSettings.PrivateKey)
		}
	}
	if pc.EnvoyMetricsService != nil {
		appendTLSCerts(pc.EnvoyMetricsService)
	}
	if pc.EnvoyAccessLogService != nil {
		appendTLSCerts(pc.EnvoyAccessLogService)
	}
	return certs
}

func constructProxyConfig() (meshconfig.ProxyConfig, error) {
	annotations, err := readPodAnnotations()
	if err != nil {
		log.Warnf("failed to read pod annotations: %v", err)
	}
	var fileMeshContents string
	if fileExists(meshConfigFile) {
		contents, err := ioutil.ReadFile(meshConfigFile)
		if err != nil {
			return meshconfig.ProxyConfig{}, fmt.Errorf("failed to read mesh config file %v: %v", meshConfigFile, err)
		}
		fileMeshContents = string(contents)
	}
	meshConfig, err := getMeshConfig(fileMeshContents, annotations[annotation.ProxyConfig.Name])
	if err != nil {
		return meshconfig.ProxyConfig{}, err
	}
	proxyConfig := mesh.DefaultProxyConfig()
	if meshConfig.DefaultConfig != nil {
		proxyConfig = *meshConfig.DefaultConfig
	}

	proxyConfig.Concurrency = int32(concurrency)
	proxyConfig.ServiceCluster = serviceCluster
	// resolve statsd address
	if proxyConfig.StatsdUdpAddress != "" {
		addr, err := proxy.ResolveAddr(proxyConfig.StatsdUdpAddress)
		if err != nil {
			// If istio-mixer.istio-system can't be resolved, skip generating the statsd config.
			// (instead of crashing). Mixer is optional.
			log.Warnf("resolve StatsdUdpAddress failed: %v", err)
			proxyConfig.StatsdUdpAddress = ""
		} else {
			proxyConfig.StatsdUdpAddress = addr
		}
	}
	if err := validation.ValidateProxyConfig(&proxyConfig); err != nil {
		return meshconfig.ProxyConfig{}, err
	}
	return applyAnnotations(proxyConfig, annotations), nil
}

// getMeshConfig gets the mesh config to use for proxy configuration
// 1. First we take the default config
// 2. Then we apply any settings from file (this comes from gateway mounting configmap)
// 3. Then we apply settings from environment variable (this comes from sidecar injection sticking meshconfig here)
// 4. Then we apply overrides from annotation (this comes from annotation on gateway, passed through downward API)
//
// Merging is done by replacement. Any fields present in the overlay will replace those existing fields, while
// untouched fields will remain untouched. This means lists will be replaced, not appended to, for example.
// 这里讨论了meshConfig的优先级，默认->configmap->环境变量(来自sidecar的注入)->注解(来自download API)
// meshConfig配置为覆盖方式
func getMeshConfig(fileOverride, annotationOverride string) (meshconfig.MeshConfig, error) {
	mc := mesh.DefaultMeshConfig()

	if fileOverride != "" {
		log.Infof("Apply mesh config from file %v", fileOverride)
		fileMesh, err := mesh.ApplyMeshConfig(fileOverride, mc)
		if err != nil || fileMesh == nil {
			return meshconfig.MeshConfig{}, fmt.Errorf("failed to unmarshal mesh config from file [%v]: %v", fileOverride, err)
		}
		mc = *fileMesh
	}

	if proxyConfigEnv != "" {
		log.Infof("Apply proxy config from env %v", proxyConfigEnv)
		envMesh, err := mesh.ApplyProxyConfig(proxyConfigEnv, mc)
		if err != nil || envMesh == nil {
			return meshconfig.MeshConfig{}, fmt.Errorf("failed to unmarshal mesh config from environment [%v]: %v", proxyConfigEnv, err)
		}
		mc = *envMesh
	}

	if annotationOverride != "" {
		log.Infof("Apply proxy config from annotation %v", annotationOverride)
		annotationMesh, err := mesh.ApplyProxyConfig(annotationOverride, mc)
		if err != nil || annotationMesh == nil {
			return meshconfig.MeshConfig{}, fmt.Errorf("failed to unmarshal mesh config from annotation [%v]: %v", annotationOverride, err)
		}
		mc = *annotationMesh
	}

	return mc, nil
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func readPodAnnotations() (map[string]string, error) {
	b, err := ioutil.ReadFile(constants.PodInfoAnnotationsPath)
	if err != nil {
		return nil, err
	}
	return bootstrap.ParseDownwardAPI(string(b))
}

// Apply any overrides to proxy config from annotations
// 覆盖config里的注解信息
func applyAnnotations(config meshconfig.ProxyConfig, annos map[string]string) meshconfig.ProxyConfig {
	if v, f := annos[annotation.SidecarDiscoveryAddress.Name]; f {
		config.DiscoveryAddress = v
	}
	if v, f := annos[annotation.SidecarStatusPort.Name]; f {
		p, err := strconv.Atoi(v)
		if err != nil {
			log.Errorf("Invalid annotation %v=%v: %v", annotation.SidecarStatusPort, p, err)
		}
		config.StatusPort = int32(p)
	}
	return config
}

func getPilotSan(discoveryAddress string) string {
	discHost := strings.Split(discoveryAddress, ":")[0]
	// For local debugging - the discoveryAddress is set to localhost, but the cert issued for normal SA.
	if discHost == "localhost" {
		discHost = "istiod.istio-system.svc"
	}
	return discHost
}

// 看来目前仅支持只kubernetes
// 如果服务注册源是kubernetes:
//   做kubernetes发现地址的切割获取控制平面命名空间
// 其他：
//   返回空字符串
func getControlPlaneNamespace(podNamespace string, discoveryAddress string) string {
	ns := ""
	if registryID == serviceregistry.Kubernetes {
		partDiscoveryAddress := strings.Split(discoveryAddress, ":")
		discoveryHostname := partDiscoveryAddress[0]
		parts := strings.Split(discoveryHostname, ".")
		if len(parts) == 1 {
			// namespace of pilot is not part of discovery address use
			// pod namespace e.g. istio-pilot:15005
			ns = podNamespace
		} else if len(parts) == 2 {
			// namespace is found in the discovery address
			// e.g. istio-pilot.istio-system:15005
			ns = parts[1]
		} else {
			// discovery address is a remote address. For remote clusters
			// only support the default config, or env variable
			ns = istioNamespaceVar.Get()
			if ns == "" {
				ns = constants.IstioSystemNamespace
			}
		}
	}
	return ns
}
