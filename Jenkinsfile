pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh './gradlew -s clean build'
      }
    }
    stage('Archive JAR') {
      steps {
        archiveArtifacts(onlyIfSuccessful: true, artifacts: 'target/Sonatype**.jar')
      }
    }
  }
}