import tkinter as tk
from tkinter import filedialog, scrolledtext
import socket
from kubernetes import client, config

def load_kubeconfig():
    filename = filedialog.askopenfilename(initialdir='~/.kube', title='Select kubeconfig file')
    kubeconfig_entry.delete(0, tk.END)
    kubeconfig_entry.insert(0, filename)

def nslookup():
    host = host_entry.get()
    try:
        ip_address = socket.gethostbyname(host)
        nslookup_label.config(text=f"IP Address: {ip_address}")
    except Exception as e:
        nslookup_label.config(text=f"Error: {e}")

def get_ingresses():
    namespace = namespace_entry.get() or 'default'
    config.load_kube_config(kubeconfig_entry.get())
    v1_net = client.NetworkingV1Api()
    core_v1_api = client.CoreV1Api()

    try:
        if namespace.lower() == 'all':
            ingresses = v1_net.list_ingress_for_all_namespaces()
        else:
            ingresses = v1_net.list_namespaced_ingress(namespace)

        output_text.delete(1.0, tk.END)  # Clear previous output
        for ingress in ingresses.items:
            for rule in ingress.spec.rules:
                http_paths = rule.http.paths if rule.http else []
                for path in http_paths:
                    service_name = path.backend.service.name
                    # Fetch service details
                    service = core_v1_api.read_namespaced_service(service_name, namespace)
                    service_selectors = service.spec.selector
                    output_text.insert(tk.END, f"Service: {service_name}, Selectors: {service_selectors}\n")

                    # Fetch endpoints for the service
                    endpoints = core_v1_api.read_namespaced_endpoints(service_name, namespace)
                    for subset in endpoints.subsets:
                        for address in subset.addresses:
                            output_text.insert(tk.END, f"Endpoint IP: {address.ip}\n")
                            # Find pods with the endpoint IP
                            pods = core_v1_api.list_namespaced_pod(namespace, field_selector=f'status.podIP={address.ip}')
                            for pod in pods.items:
                                pod_labels = pod.metadata.labels
                                output_text.insert(tk.END, f"Pod: {pod.metadata.name}, Labels: {pod_labels}\n")
                                # Compare pod labels with service selectors
                                for key, value in service_selectors.items():
                                    label_value = pod_labels.get(key, None)
                                    if label_value == value:
                                        output_text.insert(tk.END, f"Matching: {key}={value}\n", 'match')
                                    else:
                                        output_text.insert(tk.END, f"Not Matching: {key}={value}\n", 'not_match')

                    output_text.insert(tk.END, "-----\n")

    except client.exceptions.ApiException as e:
        output_text.insert(tk.END, f"Kubernetes API error: {e}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

# Setting up the main window
root = tk.Tk()
root.title("Kubernetes Ingress Checker")
root.configure(bg='#aee4ed')

# Kubeconfig file selection
tk.Label(root, text="Kubeconfig Path:").pack()
kubeconfig_entry = tk.Entry(root)
kubeconfig_entry.pack()
tk.Button(root, text="Browse", command=load_kubeconfig).pack()

# Namespace input
tk.Label(root, text="Namespace (leave blank for 'default'):").pack()
namespace_entry = tk.Entry(root)
namespace_entry.pack()

# Host URL input for nslookup
tk.Label(root, text="Host URL for nslookup:").pack()
host_entry = tk.Entry(root)
host_entry.pack()
tk.Button(root, text="Nslookup", command=nslookup).pack()
nslookup_label = tk.Label(root, text="IP Address: ")
nslookup_label.pack()

# Get ingresses button
tk.Button(root, text="Get Ingresses", command=get_ingresses).pack()

# Output text area
output_text = scrolledtext.ScrolledText(root, height=20, width=100)
output_text.pack()
output_text.tag_config('match', foreground='green')
output_text.tag_config('not_match', foreground='red')

# Run the application
root.mainloop()
