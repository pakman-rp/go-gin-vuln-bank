pipeline {
    agent any

    environment {
        SEVERITY_THRESHOLD = 'HIGH' // fail build if findings >= this severity
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }
        stage('Build') {
            steps { sh 'go mod tidy && go build ./...' }
        }
        stage('Unit Tests') {
            steps { sh 'go test ./... -v' }
        }
        stage('Secret Scan') {
            steps {
                echo 'PLACEHOLDER - run gitleaks/trufflehog CLI, publish report'
            }
        }
        stage('SAST Scan') {
            steps {
                echo 'PLACEHOLDER - run vendor SAST CLI (Checkmarx/Fortify/Semgrep/etc.)'
            }
        }
        stage('SCA + SBOM') {
            steps {
                echo 'PLACEHOLDER - run vendor SCA CLI, generate CycloneDX/SPDX SBOM'
            }
        }
        stage('Severity Gate') {
            steps {
                echo "PLACEHOLDER - fail pipeline if findings >= ${SEVERITY_THRESHOLD}"
            }
        }
    }

    post {
        always {
            echo 'Archive SAST/SCA/secret-scan reports here for POC evidence.'
        }
    }
}
