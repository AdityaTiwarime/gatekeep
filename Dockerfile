# Build a static binary, then ship it on a distroless base as a non-root user.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /gatekeep ./cmd/gatekeep

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gatekeep /gatekeep
EXPOSE 8080
ENTRYPOINT ["/gatekeep"]
CMD ["demo"]
