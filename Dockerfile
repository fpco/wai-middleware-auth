# Just a preexisting build image that has everything we need
FROM snoyberg/haskellers-build-image:e17739d1c2c043aae11924fee66c9ee4304ad37d as build

# Get the compiler in place and cached
COPY stack.yaml /tmp/stack.yaml
RUN stack setup --stack-yaml /tmp/stack.yaml

# Build just the dependencies in the cache
COPY wai-middleware-auth.cabal /tmp/
RUN stack build --only-dependencies --stack-yaml /tmp/stack.yaml

# Build the actual project
COPY . /src
RUN stack install --local-bin-path /output --stack-yaml /src/stack.yaml

# Runtime image
FROM fpco/pid1

# Set lang env var appropriately
ENV LANG C.UTF-8

# Install necessary dependencies for making SSL connections
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
  ca-certificates \
  libgmp-dev \
  netbase

# Copy over the executable from the build image
COPY --from=build /output/wai-auth /usr/local/bin/wai-auth

# Set up the entrypoint correctly for local users
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
