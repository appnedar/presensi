class RateLimiter {
    constructor() {
        this.store = new Map();
    }
    
    isLimited(key, maxRequests = 100, windowMs = 60000) {
        const now = Date.now();
        
        if (!this.store.has(key)) {
            this.store.set(key, { count: 0, resetTime: now + windowMs });
        }
        
        const bucket = this.store.get(key);
        
        if (now > bucket.resetTime) {
            bucket.count = 0;
            bucket.resetTime = now + windowMs;
        }
        
        if (bucket.count >= maxRequests) {
            return true;
        }
        
        bucket.count++;
        return false;
    }
    
    getRemaining(key, maxRequests = 100) {
        const bucket = this.store.get(key);
        return bucket ? Math.max(0, maxRequests - bucket.count) : maxRequests;
    }
    
    cleanup() {
        const now = Date.now();
        for (const [key, bucket] of this.store.entries()) {
            if (now > bucket.resetTime + 3600000) {
                this.store.delete(key);
            }
        }
    }
}

module.exports = new RateLimiter();
