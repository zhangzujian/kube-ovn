# use docker to generate code
# useage: bash ./hack/update-codegen-docker.sh

# set GOPROXY you like
GOPROXY=${GOPROXY:-"https://goproxy.cn"}

docker run -it --rm \
    -v ${PWD}:/app \
    -e GOPROXY=${GOPROXY} \
    ghcr.io/slok/kube-code-generator:v0.2.1 \
    --apis-in ./pkg/apis \
    --go-gen-out ./pkg/client \
    --boilerplate-path ./hack/boilerplate.go.txt

go mod tidy
