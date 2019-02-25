"use strict";

class Cache {
    constructor(ttl=60000) {
        this._cache = {};
        this.ttl = ttl;
        this.debug = () => {};
    }

    setDebug(debug) {
        this.debug = debug;
    }

    setTTL(ttl) {
        this.ttl = ttl;
    }

    remove(id) {
        const item = this._cache[id];
        if (item) {
            if(!!item.proxy) {
                item.proxy.close();
            }

            delete this._cache[id];
            this.debug(`Remove id '${id}'`);
        }
    }

    add(id) {
        if (!!!this._cache[id]) {
            this._cache[id] = {
                proxy: null,
                dtCreate: Date.now().valueOf(),
                dtLastQuery: Date.now().valueOf(),
                user: null
            };
        }
    }

    setUser(id, user) {
        if(!(id in this._cache)) {
            this.add(id);
        }
        this._cache[id].user = user;
    }

    user(id) {
        if(id in this._cache) {
            this._cache[id].dtLastQuery = Date.now().valueOf();
            return this._cache[id].user;
        }
        return null;
    }

    clean() {
        const now = Date.now().valueOf();
        for (const id in this._cache) {
            const interval = (now - this._cache[id].dtLastQuery);
            if (interval >= this.ttl) {
                this.debug(`Clean id '${id}' ${interval}`);
                this.remove(id);
            }
        }
    }

    getProxy(id) {
        if (!!!this._cache[id]) {
            return null;
        }
        return this._cache[id].proxy;
    }

    setProxy(id, proxy) {
        if (!!!this._cache[id]) {
            this.add(id);
        }
        this._cache[id].proxy = proxy;
    }

    closeProxy(id) {
        const item = this._cache[id];
        if (item) {
            if(!!item.proxy) {
                item.proxy.close();
                item.proxy = null;
                return true;
            }
        }

        return false;
    }

    item(id) {
        return this._cache[id];
    }

    copy(src, dst) {
        this._cache[dst] = this._cache[src];
        this.debug(`Copy '${src}' to '${dst}'`);
    }
}

module.exports = Cache;
