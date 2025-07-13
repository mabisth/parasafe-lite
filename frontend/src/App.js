import React, { useState } from 'react';
import './App.css';

const App = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!url) {
      setError('Please enter a valid URL');
      return;
    }

    setScanning(true);
    setError('');
    setScanResults(null);

    try {
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.detail || 'Scan failed');
      }

      setScanResults(data);
    } catch (err) {
      setError(err.message || 'An error occurred during scanning');
    } finally {
      setScanning(false);
    }
  };

  const getRiskColor = (risk) => {
    switch (risk?.toLowerCase()) {
      case 'high': return 'text-red-600 bg-red-100';
      case 'medium': return 'text-orange-600 bg-orange-100';
      case 'low': return 'text-yellow-600 bg-yellow-100';
      case 'info': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center space-x-4">
            {/* Logo Placeholder - Will be replaced with actual logo */}
            <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg flex items-center justify-center">
              <div className="w-8 h-8 bg-white rounded transform rotate-45"></div>
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">ParaSafe-Lite</h1>
              <p className="text-sm text-gray-600">Web Application Security Scanner</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Scan Input Section */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Security Scan</h2>
          <p className="text-gray-600 mb-6">
            Enter a website URL to scan for security vulnerabilities based on OWASP Top 10, CWE, NIST, and SANS Top 25 standards.
          </p>
          
          <div className="flex space-x-4">
            <div className="flex-1">
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                disabled={scanning}
              />
            </div>
            <button
              onClick={handleScan}
              disabled={scanning || !url}
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center space-x-2"
            >
              {scanning ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  <span>Scanning...</span>
                </>
              ) : (
                <span>Start Scan</span>
              )}
            </button>
          </div>

          {error && (
            <div className="mt-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded-lg">
              {error}
            </div>
          )}
        </div>

        {/* Scan Results */}
        {scanResults && (
          <div className="space-y-6">
            {/* Scan Summary */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan Summary</h3>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="text-center p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{scanResults.summary?.high || 0}</div>
                  <div className="text-sm text-red-700">High Risk</div>
                </div>
                <div className="text-center p-4 bg-orange-50 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">{scanResults.summary?.medium || 0}</div>
                  <div className="text-sm text-orange-700">Medium Risk</div>
                </div>
                <div className="text-center p-4 bg-yellow-50 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{scanResults.summary?.low || 0}</div>
                  <div className="text-sm text-yellow-700">Low Risk</div>
                </div>
                <div className="text-center p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{scanResults.summary?.info || 0}</div>
                  <div className="text-sm text-blue-700">Informational</div>
                </div>
              </div>
            </div>

            {/* Scan Details */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Details</h3>
              
              {scanResults.vulnerabilities && scanResults.vulnerabilities.length > 0 ? (
                <div className="space-y-4">
                  {scanResults.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-3">
                        <h4 className="font-semibold text-gray-900">{vuln.title}</h4>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getRiskColor(vuln.risk)}`}>
                          {vuln.risk?.toUpperCase()}
                        </span>
                      </div>
                      
                      <p className="text-gray-600 mb-3">{vuln.description}</p>
                      
                      {vuln.evidence && (
                        <div className="bg-gray-50 rounded p-3 mb-3">
                          <h5 className="font-medium text-gray-900 mb-2">Evidence:</h5>
                          <code className="text-sm text-gray-700 break-all">{vuln.evidence}</code>
                        </div>
                      )}
                      
                      {vuln.recommendation && (
                        <div className="bg-blue-50 rounded p-3">
                          <h5 className="font-medium text-blue-900 mb-2">Recommendation:</h5>
                          <p className="text-sm text-blue-800">{vuln.recommendation}</p>
                        </div>
                      )}
                      
                      {vuln.manual_verification && (
                        <div className="bg-green-50 rounded p-3 mt-3">
                          <h5 className="font-medium text-green-900 mb-2">Manual Verification:</h5>
                          <p className="text-sm text-green-800">{vuln.manual_verification}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <div className="text-6xl mb-4">🛡️</div>
                  <p>No significant vulnerabilities detected!</p>
                  <p className="text-sm mt-2">The basic security checks passed successfully.</p>
                </div>
              )}
            </div>

            {/* Scan Metadata */}
            {scanResults.scan_info && (
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan Information</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-gray-700">Target URL:</span>
                    <span className="ml-2 text-gray-600">{scanResults.scan_info.target_url}</span>
                  </div>
                  <div>
                    <span className="font-medium text-gray-700">Scan Time:</span>
                    <span className="ml-2 text-gray-600">{scanResults.scan_info.scan_time}</span>
                  </div>
                  {scanResults.scan_info.server_info && (
                    <div>
                      <span className="font-medium text-gray-700">Server:</span>
                      <span className="ml-2 text-gray-600">{scanResults.scan_info.server_info}</span>
                    </div>
                  )}
                  {scanResults.scan_info.technologies && (
                    <div>
                      <span className="font-medium text-gray-700">Technologies:</span>
                      <span className="ml-2 text-gray-600">{scanResults.scan_info.technologies.join(', ')}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center text-sm text-gray-500">
            <p>ParaSafe-Lite - Security scanning based on OWASP Top 10, CWE, NIST & SANS Top 25</p>
            <p className="mt-1">For educational and testing purposes only. Always obtain proper authorization before scanning.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;