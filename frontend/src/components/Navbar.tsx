import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';

export default function Navbar() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center justify-between">
      <div className="flex items-center gap-6">
        <Link to={isAdmin ? '/admin' : '/dashboard'} className="text-white font-bold text-lg flex items-center gap-2">
          <span>🔍</span> SCS
        </Link>
        {!isAdmin && (
          <>
            <Link to="/dashboard" className="text-gray-400 hover:text-white text-sm transition-colors">Dashboard</Link>
            <Link to="/scan" className="text-gray-400 hover:text-white text-sm transition-colors">New Scan</Link>
            <Link to="/history" className="text-gray-400 hover:text-white text-sm transition-colors">History</Link>
          </>
        )}
        {isAdmin && (
          <Link to="/admin" className="text-gray-400 hover:text-white text-sm transition-colors">Admin Dashboard</Link>
        )}
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${isAdmin ? 'bg-purple-900/60 text-purple-300 border border-purple-700' : 'bg-blue-900/60 text-blue-300 border border-blue-700'}`}>
            {user?.role}
          </span>
          <span className="text-gray-400 text-sm">{user?.email}</span>
        </div>
        <button onClick={handleLogout}
          className="text-gray-400 hover:text-white text-sm transition-colors">
          Logout
        </button>
      </div>
    </nav>
  );
}
