# PA

mvn -DskipTests -pl externs/pom.xml,pom-main.xml,pom-main-shaded.xml

java -jar target/closure-compiler-1.0-SNAPSHOT.jar --assume_function_wrapper --js=../benchmark/dummy/dummy.js