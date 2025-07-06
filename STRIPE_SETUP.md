# Setting Up Environment Variables for Stripe

## Quick Setup Steps:

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Get your Stripe keys:**
   - Go to [Stripe Dashboard](https://dashboard.stripe.com/apikeys)
   - Copy your **Publishable key** (starts with `pk_test_` or `pk_live_`)
   - Copy your **Secret key** (starts with `sk_test_` or `sk_live_`)

3. **Update your `.env` file:**
   Replace these lines in your `.env` file:
   ```
   STRIPE_PUBLISHABLE_KEY=pk_test_your_actual_key_here
   STRIPE_SECRET_KEY=sk_test_your_actual_key_here
   ```

4. **Restart your server:**
   ```bash
   npm start
   # or
   node server.js
   ```

## What Changed:

### Security Improvements:
- ✅ Stripe keys now loaded from environment variables
- ✅ Config endpoint provides publishable key to frontend
- ✅ Enhanced email validation with proper regex
- ✅ Better error handling for missing configuration

### User Experience Improvements:
- ✅ Auto-focus on email input when modal opens
- ✅ Enter key submits email form
- ✅ Error messages clear when user starts typing
- ✅ More specific validation error messages

### Development Benefits:
- ✅ Easy to switch between test/live environments
- ✅ Keeps sensitive data out of version control
- ✅ Better configuration management

## Testing:

1. Make sure your `.env` file has valid Stripe test keys
2. Start your server: `node server.js`
3. Open `http://localhost:3000/subscribe.html`
4. The Stripe configuration should load automatically

## Production Notes:

- Always use live keys (`pk_live_` and `sk_live_`) in production
- Never commit your `.env` file to version control
- Set environment variables directly on your hosting platform
