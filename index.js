const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require("cors")

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors())

// Config
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/pharmacy_db';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_env';
const JWT_EXPIRES_IN = '18h';

// Mongoose models


const BillSchema = new mongoose.Schema({
    customerName: { type: String, required: true },
    phone: { type: String },
    address: { type: String },
    items: [{
        medicineId: { type: String, required: true },
        medicineName: { type: String, required: true },
        requestedQuantity: { type: Number, required: true },
        usedStocks: [{
            stockId: { type: String, required: true },
            batchNo: { type: String },
            quantity: { type: Number, required: true },
            unitPrice: { type: Number, required: true },
            subtotal: { type: Number, required: true }
        }],
        lineTotal: { type: Number, required: true }, // total for this medicine (sum of usedStocks.subtotal)
        discountPercent: { type: Number, default: 0 }, // individual medicine discount
        discountAmount: { type: Number, default: 0 }, // calculated discount for this medicine
        lineTotalAfterDiscount: { type: Number, required: true } // lineTotal - discountAmount
    }],
    discountPercent: { type: Number, default: 0 }, // overall bill discount (fallback)
    totalBeforeDiscount: { type: Number, required: true },
    totalDiscountAmount: { type: Number, required: true }, // sum of all discounts
    totalAfterDiscount: { type: Number, required: true }
}, { timestamps: true });


const StockSchema = new mongoose.Schema({
    id: { type: String, required: true },
    batchNo: { type: String, required: true },
    quantity: { type: Number, required: true, min: 0 },
    expiry: { type: Date, required: true },
    price: { type: Number, required: true, min: 0 }
}, { _id: false });

const MedicineSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    stock: { type: [StockSchema], default: [] }
}, { timestamps: true });

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true }
}, { timestamps: true });

const Medicine = mongoose.model('Medicine', MedicineSchema);
const User = mongoose.model('User', UserSchema);
const Bill = mongoose.model('Bill', BillSchema);

// Auth middleware
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });
    const [scheme, token] = authHeader.split(' ');
    if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid auth header format' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        return next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// Utils
function validateStockPayload(s) {
    if (!s || typeof s !== 'object') return 'Stock must be an object';
    const required = ['id', 'batchNo', 'quantity', 'expiry', 'price'];
    for (const k of required) {
        if (!(k in s)) return `Missing stock field: ${k}`;
    }
    if (typeof s.id !== 'string' || !s.id.trim()) return 'Invalid stock id';
    if (typeof s.batchNo !== 'string' || !s.batchNo.trim()) return 'Invalid batchNo';
    if (!Number.isFinite(s.quantity) || s.quantity < 0) return 'Invalid quantity';
    if (!s.expiry || isNaN(Date.parse(s.expiry))) return 'Invalid expiry';
    if (!Number.isFinite(s.price) || s.price < 0) return 'Invalid price';
    return null;
}

// Routes
// Health
app.get('/', (req, res) => {
    res.json({ status: 'ok' });
});

// Seed default user if none exists
async function ensureDefaultUser() {
    const count = await User.countDocuments();
    if (count === 0) {
        const email = process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com';
        const password = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
        const passwordHash = await bcrypt.hash(password, 10);
        await User.create({ email, passwordHash });
        console.log(`Seeded default user -> ${email} / ${password}`);
    }
}

// Auth: login
app.post('/auth/login', async (req, res) => {
    console.log("Logging In")
    try {
        const { email, password } = req.body || {};
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ sub: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        return res.json({ token, expiresIn: JWT_EXPIRES_IN });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Add or update medicine
// If id not exists: create medicine with one stock object
// If exists: check stock id under this medicine; if exists, increase quantity; else push new stock
app.post('/medicines', authMiddleware, async (req, res) => {
    try {
        const { id, name, stock } = req.body || {};
        if (!id || typeof id !== 'string' || !id.trim()) {
            return res.status(400).json({ error: 'Medicine id is required' });
        }
        if (!name || typeof name !== 'string' || !name.trim()) {
            return res.status(400).json({ error: 'Medicine name is required' });
        }
        const stockError = validateStockPayload(stock);
        if (stockError) return res.status(400).json({ error: stockError });

        let medicine = await Medicine.findOne({ id });
        if (!medicine) {
            medicine = await Medicine.create({
                id,
                name,
                stock: [{
                    id: stock.id,
                    batchNo: stock.batchNo,
                    quantity: stock.quantity,
                    expiry: new Date(stock.expiry),
                    price: stock.price
                }]
            });
            return res.status(201).json(medicine);
        }

        const idx = medicine.stock.findIndex(s => s.id === stock.id);
        if (idx !== -1) {
            medicine.stock[idx].quantity += stock.quantity;
        } else {
            medicine.stock.push({
                id: stock.id,
                batchNo: stock.batchNo,
                quantity: stock.quantity,
                expiry: new Date(stock.expiry),
                price: stock.price
            });
        }
        await medicine.save();
        return res.json(medicine);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});



// Increment quantity by +1 for a stock under a medicine
// Body: { stockId: string }
app.post('/medicines/:id/edit', authMiddleware, async (req, res) => {
    try {
        const medicineId = req.params.id;
        const { updates } = req.body || {};

        // Validate input array
        if (!Array.isArray(updates) || updates.length === 0) {
            return res.status(400).json({ error: 'Body must contain an "updates" array with at least one item' });
        }

        // Normalize & validate updates
        const normalized = updates.map(u => {
            if (!u || typeof u !== 'object') return { valid: false, raw: u };
            const stockId = typeof u.stockId === 'string' && u.stockId.trim() ? u.stockId.trim() : null;
            const q = Number(u.quantity);
            // quantity must be finite and not 0 (0 is a no-op)
            const valid = !!stockId && Number.isFinite(q) && q !== 0;
            return { stockId, quantity: q, valid, raw: u };
        });

        const invalidItems = normalized.filter(n => !n.valid).map(n => ({ raw: n.raw }));
        const validItems = normalized.filter(n => n.valid);

        if (validItems.length === 0) {
            return res.status(400).json({ error: 'No valid update items found', invalidItems });
        }

        const medicine = await Medicine.findOne({ id: medicineId });
        if (!medicine) return res.status(404).json({ error: 'Medicine not found' });

        const updated = [];      // { stockId, delta, oldQuantity, newQuantity }
        const removed = [];      // { stockId, oldQuantity }
        const notFound = [];     // stockId[]
        const insufficient = []; // { stockId, oldQuantity, attemptedDelta }

        // Apply updates in-memory
        for (const item of validItems) {
            const idx = medicine.stock.findIndex(s => s.id === item.stockId);
            if (idx === -1) {
                notFound.push(item.stockId);
                continue;
            }

            const oldQty = Number(medicine.stock[idx].quantity || 0);
            const newQty = oldQty + item.quantity;

            if (newQty < 0) {
                // cannot make quantity negative
                insufficient.push({ stockId: item.stockId, oldQuantity: oldQty, attemptedDelta: item.quantity });
                continue;
            }

            if (newQty === 0) {
                // remove stock object
                removed.push({ stockId: item.stockId, oldQuantity: oldQty });
                medicine.stock.splice(idx, 1);
            } else {
                // update quantity
                medicine.stock[idx].quantity = newQty;
                updated.push({ stockId: item.stockId, delta: item.quantity, oldQuantity: oldQty, newQuantity: newQty });
            }
        }

        // If nothing actually applied (no updates and no removals), return 400 with details
        if (updated.length === 0 && removed.length === 0) {
            return res.status(400).json({
                error: 'No stock updates applied',
                notFound,
                insufficient,
                invalidItems
            });
        }

        await medicine.save();

        return res.json({
            message: 'Batch stock update applied',
            appliedCount: updated.length + removed.length,
            updated,
            removed,
            notFound,
            insufficient,
            invalidItems,
            medicine
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});


// Get all medicines
app.get('/medicines', authMiddleware, async (req, res) => {
    try {
        const medicines = await Medicine.find({}).lean();
        return res.json(medicines);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});


app.post('/bills', authMiddleware, async (req, res) => {
    console.log("Bills")
  try {
    const { customer = {}, items, discountPercent = 0 } = req.body || {};

    // Basic validations
    if (!customer || typeof customer !== 'object' || !customer.name || typeof customer.name !== 'string') {
      return res.status(400).json({ error: 'customer.name is required' });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'items array is required' });
    }
    const overallDiscountNum = Number(discountPercent) || 0;
    if (!Number.isFinite(overallDiscountNum) || overallDiscountNum < 0 || overallDiscountNum > 100) {
      return res.status(400).json({ error: 'discountPercent must be a number between 0 and 100' });
    }

    // Normalize items: enforce medicineId, quantity, and optional discountPercent
    const normalizedRaw = items.map(it => {
      const itemDiscountNum = Number(it && it.discountPercent) || 0;
      if (itemDiscountNum < 0 || itemDiscountNum > 100) {
        throw new Error(`Item discountPercent must be between 0 and 100 for medicine ${it.medicineId}`);
      }
      return {
        medicineId: it && typeof it.medicineId === 'string' ? it.medicineId.trim() : null,
        quantity: Number(it && it.quantity),
        discountPercent: itemDiscountNum
      };
    });

    // Validate and collect errors
    for (const it of normalizedRaw) {
      if (!it.medicineId || !Number.isFinite(it.quantity) || it.quantity <= 0) {
        return res.status(400).json({ error: 'Each item must have a valid medicineId (string) and quantity > 0', item: it });
      }
    }

    // Merge duplicates: sum quantities for same medicineId, use highest discount
    const mergedMap = new Map();
    for (const it of normalizedRaw) {
      if (!mergedMap.has(it.medicineId)) {
        mergedMap.set(it.medicineId, {
          medicineId: it.medicineId,
          quantity: 0,
          discountPercent: it.discountPercent
        });
      }
      const existing = mergedMap.get(it.medicineId);
      existing.quantity += it.quantity;
      // Use the higher discount if multiple entries for same medicine
      existing.discountPercent = Math.max(existing.discountPercent, it.discountPercent);
    }
    const normalizedItems = Array.from(mergedMap.values()); // { medicineId, quantity, discountPercent }

    // === Stage 1: build plan (read docs and plan consumption) - READS only ===
    const plan = []; // { medicine, requestedQuantity, usedStocks[], lineTotal, discountPercent, discountAmount, lineTotalAfterDiscount }
    for (const it of normalizedItems) {
      const medicine = await Medicine.findOne({ id: it.medicineId }).lean();
      if (!medicine) {
        return res.status(404).json({ error: 'Medicine not found', medicineId: it.medicineId });
      }

      // FIFO by expiry (earliest expiry first)
      const stocksSorted = Array.isArray(medicine.stock) ? [...medicine.stock].sort((a, b) => new Date(a.expiry) - new Date(b.expiry)) : [];

      let remaining = Number(it.quantity);
      const usedStocks = [];
      let lineTotal = 0;

      for (const s of stocksSorted) {
        if (remaining <= 0) break;
        const available = Number(s.quantity || 0);
        if (available <= 0) continue;
        const take = Math.min(available, remaining);
        const subtotal = take * Number(s.price || 0);
        usedStocks.push({
          stockId: s.id,
          batchNo: s.batchNo,
          quantity: take,
          unitPrice: Number(s.price || 0),
          subtotal: Math.round(subtotal * 100) / 100
        });
        lineTotal += subtotal;
        remaining -= take;
      }

      if (remaining > 0) {
        return res.status(409).json({
          error: 'Insufficient stock for medicine (based on read snapshot)',
          medicineId: medicine.id,
          medicineName: medicine.name,
          requested: it.quantity,
          available: it.quantity - remaining
        });
      }

      // Calculate discount for this medicine (use item discount or fallback to overall discount)
      const itemDiscountPercent = it.discountPercent > 0 ? it.discountPercent : overallDiscountNum;
      const roundedLineTotal = Math.round(lineTotal * 100) / 100;
      const discountAmount = Math.round((roundedLineTotal * itemDiscountPercent / 100) * 100) / 100;
      const lineTotalAfterDiscount = Math.round((roundedLineTotal - discountAmount) * 100) / 100;

      plan.push({
        medicine, // the snapshot read (lean)
        requestedQuantity: Number(it.quantity),
        usedStocks,
        lineTotal: roundedLineTotal,
        discountPercent: itemDiscountPercent,
        discountAmount: discountAmount,
        lineTotalAfterDiscount: lineTotalAfterDiscount
      });
    }

    // === Stage 2: apply conditional atomic updates + rollback on failure (no transactions) ===
    // We DO NOT remove zero-quantity entries yet. We'll do clean-up after bill save.
    const appliedUpdates = []; // { medicineId, stockId, quantity }
    const medicineIdsTouched = new Set();

    try {
      for (const p of plan) {
        const medId = p.medicine.id;
        medicineIdsTouched.add(medId);

        for (const used of p.usedStocks) {
          // Atomic conditional decrement for the specific array element
          const updateRes = await Medicine.updateOne(
            {
              id: medId,
              "stock.id": used.stockId,
              "stock.quantity": { $gte: used.quantity } // ensure enough quantity in that array element
            },
            {
              $inc: { "stock.$.quantity": -used.quantity }
            }
          );

          // updateRes may have modifiedCount/matchedCount depending on driver
          const matched = updateRes.matchedCount ?? updateRes.n ?? 0;
          const modified = updateRes.modifiedCount ?? updateRes.nModified ?? 0;

          if (!matched || !modified) {
            // Concurrent modification or insufficient qty — rollback applied updates
            for (let i = appliedUpdates.length - 1; i >= 0; --i) {
              const a = appliedUpdates[i];
              try {
                // Try to increment back; this will fail silently if the stock element was removed
                // but we didn't remove elements yet (cleanup deferred) so it should succeed.
                await Medicine.updateOne(
                  { id: a.medicineId, "stock.id": a.stockId },
                  { $inc: { "stock.$.quantity": a.quantity } }
                );
              } catch (e) {
                // ignore rollback failure attempts
                console.error('Rollback increment failed for', a, e);
              }
            }

            return res.status(409).json({
              error: 'Concurrent modification or insufficient stock during apply',
              failedStockId: used.stockId,
              medicineId: medId
            });
          }

          appliedUpdates.push({ medicineId: medId, stockId: used.stockId, quantity: used.quantity });
        }
      }

      // === Stage 3: create Bill doc with discount calculations ===
      const itemsForBill = plan.map(p => ({
        medicineId: p.medicine.id,
        medicineName: p.medicine.name,
        requestedQuantity: p.requestedQuantity,
        usedStocks: p.usedStocks,
        lineTotal: p.lineTotal,
        discountPercent: p.discountPercent,
        discountAmount: p.discountAmount,
        lineTotalAfterDiscount: p.lineTotalAfterDiscount
      }));

      const totalBeforeDiscount = Math.round(plan.reduce((acc, p) => acc + p.lineTotal, 0) * 100) / 100;
      const totalDiscountAmount = Math.round(plan.reduce((acc, p) => acc + p.discountAmount, 0) * 100) / 100;
      const totalAfterDiscount = Math.round(plan.reduce((acc, p) => acc + p.lineTotalAfterDiscount, 0) * 100) / 100;

      const bill = new Bill({
        customerName: customer.name,
        phone: customer.phone || undefined,
        address: customer.address || undefined,
        items: itemsForBill,
        discountPercent: overallDiscountNum, // overall fallback discount
        totalBeforeDiscount,
        totalDiscountAmount,
        totalAfterDiscount
      });

      await bill.save();

      // === Stage 4: Cleanup zero-quantity stock array entries (best-effort) ===
      // Do this after bill saved so rollback is still possible if something failed earlier.
      try {
        const meds = Array.from(medicineIdsTouched);
        for (const mId of meds) {
          await Medicine.updateOne(
            { id: mId },
            { $pull: { stock: { quantity: { $lte: 0 } } } }
          );
        }
      } catch (cleanupErr) {
        // cleanup failure shouldn't fail the whole operation; just log it
        console.error('Warning: failed to clean up zero-qty stock entries', cleanupErr);
      }

      // Build response payload
      const responsePayload = {
        message: 'Bill created and stock updated (no transactions, conditional updates used)',
        bill,
        summary: {
          totalBeforeDiscount,
          overallDiscountPercent: overallDiscountNum,
          totalDiscountAmount,
          totalAfterDiscount
        },
        items: itemsForBill,
        updatedMedicines: plan.map(p => ({
          id: p.medicine.id,
          name: p.medicine.name,
          requestedQuantity: p.requestedQuantity,
          usedStocks: p.usedStocks,
          lineTotal: p.lineTotal,
          discountPercent: p.discountPercent,
          discountAmount: p.discountAmount,
          lineTotalAfterDiscount: p.lineTotalAfterDiscount
        }))
      };

      return res.status(201).json(responsePayload);

    } catch (applyErr) {
      // Unexpected error during apply -> attempt rollback of appliedUpdates
      for (let i = appliedUpdates.length - 1; i >= 0; --i) {
        const a = appliedUpdates[i];
        try {
          await Medicine.updateOne(
            { id: a.medicineId, "stock.id": a.stockId },
            { $inc: { "stock.$.quantity": a.quantity } }
          );
        } catch (e) {
          // ignore rollback errors
          console.error('Rollback increment failed for', a, e);
        }
      }
      console.error('Error applying stock updates', applyErr);
      return res.status(500).json({ error: 'Internal server error during stock update' });
    }

  } catch (err) {
    console.error('Error creating bill', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all bills created in a timestamp range
app.post('/bills/query', authMiddleware, async (req, res) => {
    try {
        const { from, to } = req.body || {};

        if (!from || !to) {
            return res.status(400).json({ error: 'Both "from" and "to" timestamps are required' });
        }

        const fromDate = new Date(from);
        const toDate = new Date(to);

        if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
            return res.status(400).json({ error: 'Invalid timestamp format' });
        }

        if (fromDate > toDate) {
            return res.status(400).json({ error: '"from" timestamp must be before "to"' });
        }

        const bills = await Bill.find({
            createdAt: { $gte: fromDate, $lte: toDate }
        }).lean();

        return res.json({ count: bills.length, bills });

    } catch (err) {
        console.error('Error querying bills by timestamp', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/bills/daily-summary', authMiddleware, async (req, res) => {
    try {
        const { from, to } = req.body || {};

        if (!from || !to) {
            return res.status(400).json({ error: '"from" and "to" timestamps are required' });
        }

        const fromDate = new Date(from);
        const toDate = new Date(to);

        if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
            return res.status(400).json({ error: 'Invalid timestamp format' });
        }

        if (fromDate > toDate) {
            return res.status(400).json({ error: '"from" must be before "to"' });
        }

        const dailyAggregation = await Bill.aggregate([
            {
                $match: {
                    createdAt: { $gte: fromDate, $lte: toDate }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$createdAt" },
                        month: { $month: "$createdAt" },
                        day: { $dayOfMonth: "$createdAt" }
                    },
                    totalBeforeDiscount: { $sum: "$totalBeforeDiscount" }
                }
            },
            {
                $sort: { "_id.year": -1, "_id.month": -1, "_id.day": -1 }
            },
            {
                $limit: 10
            }
        ]);

        // Format result into { date: "YYYY-MM-DD", totalBeforeDiscount: number }
        const result = dailyAggregation.map(item => {
            const { year, month, day } = item._id;
            const dateStr = `${year.toString().padStart(4, '0')}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
            return {
                date: dateStr,
                totalBeforeDiscount: Math.round(item.totalBeforeDiscount * 100) / 100
            };
        });

        return res.json({ data: result });

    } catch (err) {
        console.error('Error fetching daily summary', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /bills/old
// Query params:
//   - page (1-based integer, default 1)
//   - q    (optional) case-insensitive search string for customerName
// Behavior:
//   - fixed page size of 50
//   - if q provided, search across all bills by customerName (case-insensitive partial match)
//   - otherwise, return page of all bills (newest first)
app.get('/bills/old', authMiddleware, async (req, res) => {
  try {
    const PAGE_SIZE = 50;
    const page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);

    const q = (req.query.q || '').trim();

    // Build Mongo query
    const mongoQuery = {};
    if (q) {
      // case-insensitive partial match on customerName
      // use anchored regex for partial anywhere match, escape user input
      const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      mongoQuery.customerName = { $regex: escaped, $options: 'i' };
    }

    const skip = (page - 1) * PAGE_SIZE;

    // Run both queries in parallel: results + total count
    const [bills, total] = await Promise.all([
      Bill.find(mongoQuery)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(PAGE_SIZE)
        .lean(),
      Bill.countDocuments(mongoQuery)
    ]);

    return res.json({
      count: bills.length,
      total,
      page,
      limit: PAGE_SIZE,
      bills
    });
  } catch (err) {
    console.error('Error fetching old bills', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


// Connect DB and start server
async function start() {
    try {
        await mongoose.connect(MONGODB_URI, { autoIndex: true });
        await ensureDefaultUser();
        app.listen(PORT,"0.0.0.0", () => console.log(`Server listening on port ${PORT}`));
    } catch (err) {
        console.error('Failed to start server', err);
        process.exit(1);
    }
}

// start();

mongoose.connect(MONGODB_URI, { autoIndex: true })
  .then(() => ensureDefaultUser().catch(e => console.error('seed err', e)))
  .catch(err => {
    console.error('Mongoose connect error on startup', err);
    // Note: don't process.exit in serverless environment
  });

// Export app for Vercel
module.exports = app;


