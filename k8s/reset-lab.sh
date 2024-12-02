kubectl delete ns brewz
helm uninstall nginx-ingress -n nginx-ingress
helm repo remove nginx-stable
