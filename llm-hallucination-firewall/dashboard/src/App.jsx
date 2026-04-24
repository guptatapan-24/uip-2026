import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Menu, AlertCircle, BarChart3, Lock, Settings } from 'lucide-react';

/**
 * Main LLM Hallucination Firewall Dashboard
 * 
 * Scaffolded React component with route placeholders for five views:
 * 1. Validation Dashboard - Real-time decision outcomes
 * 2. Decision History - Filterable audit trail
 * 3. Policy Management - Decision policy profiles (SOC_ADMIN only)
 * 4. Metrics & Monitoring - Prometheus metrics visualization
 * 5. Settings - User preferences and JWT token management
 * 
 * TODO: Implement API integration to gateway service
 * TODO: Implement WebSocket for real-time updates
 * TODO: Build analyst decision override UI
 */

function App() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [userRole, setUserRole] = useState('SOC_ANALYST'); // TODO: Get from JWT

  return (
    <Router>
      <div className="min-h-screen bg-gray-900 text-gray-100">
        {/* Navigation Header */}
        <header className="bg-gray-800 border-b border-gray-700">
          <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
            <Link to="/" className="flex items-center space-x-2">
              <Lock className="w-6 h-6 text-blue-500" />
              <h1 className="text-xl font-bold">LLM Hallucination Firewall</h1>
            </Link>
            
            <nav className="hidden md:flex space-x-6">
              <Link to="/" className="hover:text-blue-400 transition">Dashboard</Link>
              <Link to="/decisions" className="hover:text-blue-400 transition">Decisions</Link>
              <Link to="/metrics" className="hover:text-blue-400 transition">Metrics</Link>
              {userRole === 'SOC_ADMIN' && (
                <Link to="/policy" className="hover:text-blue-400 transition">Policy</Link>
              )}
              <Link to="/settings" className="hover:text-blue-400 transition">Settings</Link>
            </nav>

            <button
              className="md:hidden p-2"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              <Menu className="w-6 h-6" />
            </button>
          </div>

          {/* Mobile Menu */}
          {isMenuOpen && (
            <div className="md:hidden bg-gray-700 px-4 py-2 space-y-2">
              <Link to="/" className="block hover:text-blue-400">Dashboard</Link>
              <Link to="/decisions" className="block hover:text-blue-400">Decisions</Link>
              <Link to="/metrics" className="block hover:text-blue-400">Metrics</Link>
              {userRole === 'SOC_ADMIN' && (
                <Link to="/policy" className="block hover:text-blue-400">Policy</Link>
              )}
              <Link to="/settings" className="block hover:text-blue-400">Settings</Link>
            </div>
          )}
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 py-8">
          <Routes>
            <Route path="/" element={<DashboardView />} />
            <Route path="/decisions" element={<DecisionsView />} />
            <Route path="/metrics" element={<MetricsView />} />
            {userRole === 'SOC_ADMIN' && (
              <Route path="/policy" element={<PolicyView />} />
            )}
            <Route path="/settings" element={<SettingsView />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

/**
 * Dashboard View: Real-time validation outcome statistics
 * 
 * TODO: Connect to /v1/metrics/outcomes endpoint
 * TODO: Display pie chart of ALLOW | FLAG | BLOCK | CORRECT outcomes
 * TODO: Show recent decisions with risk scores
 * TODO: Display validation latency p50/p95/p99
 */
function DashboardView() {
  return (
    <div className="space-y-6">
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h2 className="text-2xl font-bold mb-4 flex items-center space-x-2">
          <BarChart3 className="w-6 h-6" />
          <span>Validation Dashboard</span>
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Outcome Cards */}
          <div className="bg-green-900 bg-opacity-30 rounded p-4 border border-green-700">
            <div className="text-sm text-gray-400">ALLOW</div>
            <div className="text-3xl font-bold text-green-400">142</div>
            <div className="text-xs text-gray-500 mt-1">Last 24h</div>
          </div>

          <div className="bg-yellow-900 bg-opacity-30 rounded p-4 border border-yellow-700">
            <div className="text-sm text-gray-400">FLAG</div>
            <div className="text-3xl font-bold text-yellow-400">38</div>
            <div className="text-xs text-gray-500 mt-1">Last 24h</div>
          </div>

          <div className="bg-red-900 bg-opacity-30 rounded p-4 border border-red-700">
            <div className="text-sm text-gray-400">BLOCK</div>
            <div className="text-3xl font-bold text-red-400">12</div>
            <div className="text-xs text-gray-500 mt-1">Last 24h</div>
          </div>

          <div className="bg-blue-900 bg-opacity-30 rounded p-4 border border-blue-700">
            <div className="text-sm text-gray-400">CORRECT</div>
            <div className="text-3xl font-bold text-blue-400">5</div>
            <div className="text-xs text-gray-500 mt-1">Last 24h</div>
          </div>
        </div>

        <div className="mt-6 bg-gray-700 rounded p-4">
          <p className="text-sm text-gray-400">
            📊 Recharts pie chart placeholder - Show decision outcome distribution
          </p>
        </div>
      </div>

      {/* Recent Decisions */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-lg font-bold mb-4">Recent Decisions</h3>
        <div className="space-y-2">
          {[1, 2, 3].map(i => (
            <div key={i} className="bg-gray-700 rounded p-3 flex justify-between items-center">
              <div>
                <div className="text-sm font-mono">Alert #{i}</div>
                <div className="text-xs text-gray-400">Risk: 0.72 | Policy: default</div>
              </div>
              <span className="px-3 py-1 bg-yellow-500 bg-opacity-20 text-yellow-300 rounded text-sm">
                FLAG
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/**
 * Decisions View: Filterable decision history with pagination
 * 
 * TODO: Connect to /v1/decisions endpoint
 * TODO: Implement filtering by outcome, date range, alert_id
 * TODO: Add pagination controls
 * TODO: Show decision detail modal on click
 * TODO: Allow analyst override (SOC_ADMIN only)
 */
function DecisionsView() {
  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <h2 className="text-2xl font-bold mb-6">Decision History</h2>
      
      {/* Filters */}
      <div className="bg-gray-700 rounded p-4 mb-6 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            type="text"
            placeholder="Alert ID..."
            className="bg-gray-600 rounded px-3 py-2 text-sm text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <select className="bg-gray-600 rounded px-3 py-2 text-sm text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option>All Outcomes</option>
            <option>ALLOW</option>
            <option>FLAG</option>
            <option>BLOCK</option>
            <option>CORRECT</option>
          </select>
          <input
            type="date"
            className="bg-gray-600 rounded px-3 py-2 text-sm text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <button className="w-full md:w-auto bg-blue-600 hover:bg-blue-700 rounded px-4 py-2 text-sm font-medium transition">
          Search
        </button>
      </div>

      {/* Decision Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-600">
              <th className="text-left py-3 px-2">Decision ID</th>
              <th className="text-left py-3 px-2">Alert ID</th>
              <th className="text-left py-3 px-2">Outcome</th>
              <th className="text-left py-3 px-2">Risk Score</th>
              <th className="text-left py-3 px-2">Created</th>
              <th className="text-left py-3 px-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3, 4, 5].map(i => (
              <tr key={i} className="border-b border-gray-700 hover:bg-gray-700 transition">
                <td className="py-3 px-2 font-mono text-xs">dec-{i}...</td>
                <td className="py-3 px-2">ALT-2024-{i}</td>
                <td className="py-3 px-2">
                  <span className={`px-2 py-1 rounded text-xs ${
                    i % 3 === 0 ? 'bg-green-500 bg-opacity-20 text-green-300' :
                    i % 3 === 1 ? 'bg-yellow-500 bg-opacity-20 text-yellow-300' :
                    'bg-red-500 bg-opacity-20 text-red-300'
                  }`}>
                    {i % 3 === 0 ? 'ALLOW' : i % 3 === 1 ? 'FLAG' : 'BLOCK'}
                  </span>
                </td>
                <td className="py-3 px-2">{(0.5 + Math.random() * 0.5).toFixed(2)}</td>
                <td className="py-3 px-2 text-gray-400 text-xs">2024-01-{15 + i}</td>
                <td className="py-3 px-2">
                  <button className="text-blue-400 hover:text-blue-300 text-xs">View</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Metrics View: Prometheus metrics visualization
 * 
 * TODO: Connect to /v1/metrics/performance endpoint
 * TODO: Display validation latency trends (p50, p95, p99)
 * TODO: Show RAG retrieval quality metrics
 * TODO: Display decision distribution over time
 * TODO: Show LLM verifier circuit breaker status
 */
function MetricsView() {
  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">System Metrics & Monitoring</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-lg font-bold mb-4">Validation Latency</h3>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">p50</span>
              <span className="font-mono">145ms</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">p95</span>
              <span className="font-mono">523ms</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">p99</span>
              <span className="font-mono">1247ms</span>
            </div>
          </div>
          <div className="mt-6 bg-gray-700 rounded p-4">
            <p className="text-xs text-gray-400">📈 Recharts line chart placeholder</p>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-lg font-bold mb-4">RAG Retrieval Quality</h3>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Avg Similarity</span>
              <span className="font-mono">0.78</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Success Rate</span>
              <span className="font-mono">96.2%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Avg Retrieval Time</span>
              <span className="font-mono">52ms</span>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-lg font-bold mb-4">System Status</h3>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span>PostgreSQL</span>
            <span className="w-3 h-3 bg-green-500 rounded-full"></span>
          </div>
          <div className="flex items-center justify-between">
            <span>Redis</span>
            <span className="w-3 h-3 bg-green-500 rounded-full"></span>
          </div>
          <div className="flex items-center justify-between">
            <span>Ollama / LLM Verifier</span>
            <span className="w-3 h-3 bg-yellow-500 rounded-full"></span>
          </div>
          <div className="flex items-center justify-between">
            <span>FAISS Index</span>
            <span className="w-3 h-3 bg-green-500 rounded-full"></span>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Policy View: Decision policy profile management (SOC_ADMIN only)
 * 
 * TODO: Connect to /v1/policy/profiles endpoint
 * TODO: Display current active policy profile
 * TODO: Allow creation/editing of policy profiles
 * TODO: Show threshold and weight configurations
 * TODO: Implement policy activation UI
 */
function PolicyView() {
  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <h2 className="text-2xl font-bold mb-6 flex items-center space-x-2">
        <Settings className="w-6 h-6" />
        <span>Policy Profiles (SOC_ADMIN)</span>
      </h2>

      <div className="bg-blue-900 bg-opacity-20 border border-blue-700 rounded p-4 mb-6">
        <div className="flex items-start space-x-2">
          <AlertCircle className="w-5 h-5 text-blue-400 mt-0.5" />
          <div className="text-sm">
            <div className="font-semibold">Active Profile: default</div>
            <div className="text-gray-400 mt-1">Standard SOC policy with balanced thresholds</div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {['default', 'aggressive', 'lenient', 'critical_response'].map(profile => (
          <div key={profile} className="bg-gray-700 rounded p-4 border border-gray-600">
            <div className="flex justify-between items-start mb-3">
              <div>
                <div className="font-semibold capitalize">{profile}</div>
                <div className="text-sm text-gray-400">Thresholds and weights...</div>
              </div>
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm transition">
                Edit
              </button>
            </div>
          </div>
        ))}
      </div>

      <button className="mt-6 w-full bg-green-600 hover:bg-green-700 rounded px-4 py-2 font-medium transition">
        + Create New Policy
      </button>
    </div>
  );
}

/**
 * Settings View: User preferences and JWT token management
 * 
 * TODO: Display current user role and permissions
 * TODO: Allow JWT token regeneration
 * TODO: Show audit log of user actions
 * TODO: Implement theme switcher (dark/light)
 * TODO: Display API documentation links
 */
function SettingsView() {
  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Settings</h2>

      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-lg font-bold mb-4">User Profile</h3>
        <div className="space-y-3">
          <div>
            <label className="text-sm text-gray-400">Username</label>
            <div className="text-base mt-1">analyst@company.com</div>
          </div>
          <div>
            <label className="text-sm text-gray-400">Role</label>
            <div className="text-base mt-1">SOC_ANALYST</div>
          </div>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-lg font-bold mb-4">API Token</h3>
        <div className="bg-gray-700 rounded p-3 font-mono text-sm text-yellow-300 break-all">
          eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
        </div>
        <button className="mt-4 px-4 py-2 bg-orange-600 hover:bg-orange-700 rounded text-sm transition">
          Regenerate Token
        </button>
      </div>

      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-lg font-bold mb-4">Resources</h3>
        <ul className="space-y-2 text-sm">
          <li>
            <a href="http://localhost:8000/docs" className="text-blue-400 hover:text-blue-300">
              → API Documentation (Swagger)
            </a>
          </li>
          <li>
            <a href="http://localhost:9090" className="text-blue-400 hover:text-blue-300">
              → Prometheus Metrics
            </a>
          </li>
          <li>
            <a href="http://localhost:3000/grafana" className="text-blue-400 hover:text-blue-300">
              → Grafana Dashboards
            </a>
          </li>
        </ul>
      </div>
    </div>
  );
}

export default App;
