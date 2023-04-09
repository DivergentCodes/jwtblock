FROM scratch
COPY jwt-block /jwt-block
ENTRYPOINT ["/jwt-block"]
CMD ["serve"]
