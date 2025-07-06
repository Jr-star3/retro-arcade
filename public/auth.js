// auth.js - Enhanced Authentication & Authorization Utility
class AuthManager {
  constructor() {
    this.baseURL = window.location.origin;
    this.tokenKey = 'token';
    this.userEmailKey = 'userEmail';
    this.subscribedKey = 'subscribed';
  }

  // Enhanced notification system (matches the style from other pages)
  showNotification(message, type = 'info') {
    // Try to use existing notification system
    if (window.showNotification) {
      window.showNotification(message, type);
      return;
    }
    
    // Fallback: create notification if none exists
    let notification = document.getElementById('auth-notification');
    if (!notification) {
      notification = document.createElement('div');
      notification.id = 'auth-notification';
      notification.style.cssText = `
        position: fixed; top: 20px; right: 20px; z-index: 10000;
        background: linear-gradient(135deg, #0ff, #00aa88);
        color: #000; padding: 15px 20px; border-radius: 8px;
        border: 2px solid #0ff; font-family: 'Press Start 2P', monospace;
        font-size: 0.8rem; font-weight: bold; max-width: 300px;
        box-shadow: 0 4px 12px rgba(0, 255, 255, 0.3);
        transform: translateX(400px); transition: transform 0.3s ease;
      `;
      document.body.appendChild(notification);
    }
    
    // Update notification based on type
    if (type === 'error') {
      notification.style.background = 'linear-gradient(135deg, #ff0040, #aa0020)';
      notification.style.borderColor = '#ff0040';
      notification.style.color = '#fff';
    } else if (type === 'warning') {
      notification.style.background = 'linear-gradient(135deg, #ff0, #aa8800)';
      notification.style.borderColor = '#ff0';
      notification.style.color = '#000';
    }
    
    notification.textContent = message;
    notification.style.transform = 'translateX(0)';
    
    setTimeout(() => {
      notification.style.transform = 'translateX(400px)';
    }, 4000);
  }

  // Clear all authentication data
  clearAuthData() {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.userEmailKey);
    localStorage.removeItem(this.subscribedKey);
  }

  // Get stored authentication data
  getAuthData() {
    return {
      token: localStorage.getItem(this.tokenKey),
      email: localStorage.getItem(this.userEmailKey),
      subscribed: localStorage.getItem(this.subscribedKey) === 'true'
    };
  }

  // Store authentication data
  setAuthData(token, email, subscribed) {
    localStorage.setItem(this.tokenKey, token);
    localStorage.setItem(this.userEmailKey, email);
    localStorage.setItem(this.subscribedKey, subscribed ? 'true' : 'false');
  }

  // Enhanced authentication check with better error handling
  async checkAuthAndSubscription(options = {}) {
    const {
      requireSubscription = true,
      showNotifications = true,
      redirectDelay = 1500
    } = options;

    try {
      const { token } = this.getAuthData();
      
      if (!token) {
        if (showNotifications) {
          this.showNotification('🔐 Please log in to access this content', 'warning');
        }
        setTimeout(() => {
          window.location.href = 'index.html';
        }, redirectDelay);
        return { success: false, reason: 'no_token' };
      }

      // Verify token with backend
      const response = await fetch(`${this.baseURL}/me`, {
        method: 'GET',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        // Handle different error types
        if (response.status === 401 || response.status === 403) {
          this.clearAuthData();
          if (showNotifications) {
            this.showNotification('🔐 Session expired. Please log in again.', 'warning');
          }
          setTimeout(() => {
            window.location.href = 'index.html';
          }, redirectDelay);
          return { success: false, reason: 'invalid_token' };
        } else {
          throw new Error(`Server error: ${response.status}`);
        }
      }

      const userData = await response.json();
      const user = userData.data || userData; // Handle different response formats

      // Update stored user data with latest from server
      this.setAuthData(token, user.email, user.subscribed);

      // Check subscription requirement
      if (requireSubscription && !user.subscribed) {
        if (showNotifications) {
          this.showNotification('⭐ Premium subscription required for full access!', 'warning');
        }
        setTimeout(() => {
          window.location.href = 'subscribe.html';
        }, redirectDelay);
        return { success: false, reason: 'no_subscription' };
      }

      if (showNotifications && user.subscribed) {
        this.showNotification('🎮 Welcome back, premium member!', 'success');
      }

      return { 
        success: true, 
        user: {
          email: user.email,
          subscribed: user.subscribed,
          lastLogin: user.lastLogin
        }
      };

    } catch (error) {
      console.error('Authentication check failed:', error);
      
      if (showNotifications) {
        this.showNotification('⚠️ Connection error. Please check your internet and try again.', 'error');
      }
      
      return { success: false, reason: 'network_error', error };
    }
  }

  // Check if user is logged in (without requiring subscription)
  async isAuthenticated() {
    const result = await this.checkAuthAndSubscription({ 
      requireSubscription: false, 
      showNotifications: false 
    });
    return result.success;
  }

  // Check subscription status only
  async hasSubscription() {
    const { subscribed } = this.getAuthData();
    
    // If we have cached data, return it immediately
    if (subscribed !== null) {
      return subscribed;
    }
    
    // Otherwise, fetch from server
    const result = await this.checkAuthAndSubscription({ 
      requireSubscription: false, 
      showNotifications: false 
    });
    
    return result.success && result.user?.subscribed;
  }

  // Logout function
  logout(showNotification = true) {
    this.clearAuthData();
    if (showNotification) {
      this.showNotification('👋 Logged out successfully!', 'info');
    }
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1000);
  }
}

// Create global instance
const authManager = new AuthManager();

// Backward compatibility - keep the original function for existing code
async function checkAuthAndSubscription() {
  return await authManager.checkAuthAndSubscription();
}

// Export additional utility functions for convenience
window.authManager = authManager;
window.checkAuth = () => authManager.isAuthenticated();
window.checkSubscription = () => authManager.hasSubscription();
window.logout = () => authManager.logout();