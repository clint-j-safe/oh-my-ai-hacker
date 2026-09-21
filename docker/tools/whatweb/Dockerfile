# Per-tool Alpine container: whatweb (Ruby)
FROM ruby:3.2-alpine
RUN apk add --no-cache git && gem install whatweb
ENTRYPOINT ["whatweb"]
