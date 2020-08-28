pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh './mvnw clean verify -B -Dbuildnum=${BUILD_NUMBER}'
      }
    }
    stage('Archive JAR') {
      steps {
        archiveArtifacts(onlyIfSuccessful: true, artifacts: '**/target/sonatype-plugin**.jar')
        archiveArtifacts(onlyIfSuccessful: true, artifacts: '**/target/SonatypeFortifyIntegration**.jar')
        archiveArtifacts(onlyIfSuccessful: true, artifacts: '**/target/SonatypeFortifyBundle**.zip')
      }
    }
  }
}
