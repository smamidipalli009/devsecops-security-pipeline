# Stage 1: build the fat JAR
FROM maven:3.9-eclipse-temurin-17-alpine AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

# Stage 2: minimal distroless runtime — no shell, no package manager
FROM gcr.io/distroless/java17-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/target/java-demo-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
