FROM ubuntu
MAINTAINER Prasad Ghangal <prasad.ghangal@gmail.com>
ADD vault-controller /vault-controller
ENTRYPOINT ["/vault-controller"]
