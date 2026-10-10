import { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  FlaskConical,
  History,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  ScanLine,
  ShieldCheck,
  Sun,
  X,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

type Theme = 'light' | 'dark';

const navigation = [
  { to: '/dashboard', label: 'Dashboard', Icon: LayoutDashboard },
  { to: '/scan', label: 'Scan Contract', Icon: ScanLine },
  { to: '/history', label: 'Audit History', Icon: History },
  { to: '/trust-registry', label: 'Trust Registry', Icon: ShieldCheck },
  { to: '/evaluation', label: 'Evaluation Suite', Icon: FlaskConical },
];

export default function Navbar() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('smai_theme');
    return saved === 'light' || saved === 'dark' ? saved : 'dark';
  });

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');
    root.classList.toggle('light', theme === 'light');
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    localStorage.setItem('smai_theme', theme);
  }, [theme]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const toggleTheme = () => setTheme(current => current === 'dark' ? 'light' : 'dark');
  const links = [
    ...navigation,
    ...(isAdmin ? [{ to: '/admin', label: 'Admin Console', Icon: ShieldCheck }] : []),
  ];

  const renderLinks = (mobile = false) => links.map(({ to, label, Icon }) => {
    const active = location.pathname === to || (to !== '/dashboard' && location.pathname.startsWith(`${to}/`));
    return (
      <Link
        key={to}
        to={to}
        onClick={() => mobile && setMobileOpen(false)}
        aria-current={active ? 'page' : undefined}
        className={`smai-nav__link ${active ? 'smai-nav__link--active' : ''}`}
      >
        <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
        <span>{label}</span>
      </Link>
    );
  });

  const themeButton = (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label="Toggle color theme"
      title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
      className="smai-nav__theme"
    >
      {theme === 'dark' ? <Sun aria-hidden="true" className="h-4 w-4" /> : <Moon aria-hidden="true" className="h-4 w-4" />}
      <span>{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
    </button>
  );

  return (
    <nav className="smai-nav" aria-label="Main navigation">
      <aside className="smai-nav__sidebar" aria-label="SMAI navigation">
        <Link to="/dashboard" className="smai-nav__brand">
          <span className="smai-nav__brand-icon"><ShieldCheck aria-hidden="true" className="h-4 w-4" /></span>
          <span className="smai-nav__brand-name">SMAI Scanner</span>
        </Link>

        <p className="smai-nav__section-label">Workspace</p>
        <div className="smai-nav__links">{renderLinks()}</div>

        <div className="smai-nav__footer">
          <div className="smai-nav__account">
            <span className="smai-nav__avatar" aria-hidden="true">{user?.email?.[0]?.toUpperCase() || 'S'}</span>
            <span className="smai-nav__account-copy">
              <span className="smai-nav__account-email">{user?.email}</span>
              <span className="smai-nav__account-role">{user?.role}</span>
            </span>
            <button type="button" onClick={handleLogout} className="smai-nav__logout" aria-label="Log out" title="Log out">
              <LogOut aria-hidden="true" className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      <div className="smai-nav__toolbar">
        <div className="smai-nav__toolbar-actions">
          <Link to="/scan" className="smai-nav__new-scan"><ScanLine aria-hidden="true" className="h-3.5 w-3.5" />New Scan</Link>
          <div className="smai-nav__desktop-theme">{themeButton}</div>
        </div>
      </div>

      <div className="smai-nav__mobile">
        <Link to="/dashboard" className="smai-nav__mobile-brand">
          <span className="smai-nav__brand-icon"><ShieldCheck aria-hidden="true" className="h-4 w-4" /></span>
          <span>SMAI Scanner</span>
        </Link>
        <div className="smai-nav__mobile-actions">
          <button type="button" onClick={toggleTheme} aria-label="Toggle color theme" className="smai-nav__icon-button">
            {theme === 'dark' ? <Sun aria-hidden="true" className="h-4 w-4" /> : <Moon aria-hidden="true" className="h-4 w-4" />}
          </button>
          <button type="button" onClick={() => setMobileOpen(open => !open)} aria-label="Toggle navigation menu" aria-expanded={mobileOpen} className="smai-nav__icon-button">
            {mobileOpen ? <X aria-hidden="true" className="h-5 w-5" /> : <Menu aria-hidden="true" className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <div className="smai-nav__mobile-drawer">
          <button type="button" className="smai-nav__backdrop" aria-label="Close navigation menu" onClick={() => setMobileOpen(false)} />
          <div className="smai-nav__mobile-panel">
            <div className="smai-nav__mobile-panel-head">
              <span className="smai-nav__mobile-brand"><span className="smai-nav__brand-icon"><ShieldCheck aria-hidden="true" className="h-4 w-4" /></span>SMAI Scanner</span>
              <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation menu" className="smai-nav__icon-button"><X aria-hidden="true" className="h-5 w-5" /></button>
            </div>
            <p className="smai-nav__section-label">Workspace</p>
            <div className="smai-nav__links">{renderLinks(true)}</div>
            <div className="smai-nav__mobile-bottom">
              {themeButton}
              <div className="smai-nav__account">
                <span className="smai-nav__avatar" aria-hidden="true">{user?.email?.[0]?.toUpperCase() || 'S'}</span>
                <span className="smai-nav__account-copy"><span className="smai-nav__account-email">{user?.email}</span><span className="smai-nav__account-role">{user?.role}</span></span>
                <button type="button" onClick={handleLogout} className="smai-nav__logout" aria-label="Log out" title="Log out"><LogOut aria-hidden="true" className="h-4 w-4" /></button>
              </div>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
