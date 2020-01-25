# PA

## Build via command line

> mvn -DskipTests -pl externs/pom.xml,pom-main.xml,pom-main-shaded.xml

## Execute via command line

> java -jar target/closure-compiler-1.0-SNAPSHOT.jar --assume_function_wrapper --js=<relative path to the JS file>