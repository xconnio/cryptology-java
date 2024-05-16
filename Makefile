build:
	./gradlew build

test:
	./gradlew test

source:
	./gradlew source

java-docs:
	./gradlew javadocJar

all: build test source java-docs
