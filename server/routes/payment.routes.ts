/**
 * Payment Routes
 *
 * Handles payment-related requests
 * Currently returns mock responses - real payment integration can be added later
 */

import { Router, Request, Response } from 'express';
import { asyncHandler } from '../middleware/error-handler';
import { verifyPayment } from '../services/payment.service';

const router = Router();

/**
 * POST /api/payment/verify
 * Verify payment token
 */
router.post(
  '/verify',
  asyncHandler(async (req: Request, res: Response) => {
    const { paymentToken } = req.body;

    if (!paymentToken) {
      return res.status(400).json({
        error: 'Payment token is required',
      });
    }

    const isValid = await verifyPayment(paymentToken);

    res.json({
      success: isValid,
      message: isValid
        ? 'Payment verified successfully'
        : 'Payment verification failed',
    });
  })
);

/**
 * POST /api/payment/create-checkout
 * Create payment checkout session
 *
 * TODO: Implement Stripe/İyzico checkout session creation
 */
router.post(
  '/create-checkout',
  asyncHandler(async (req: Request, res: Response) => {
    // Mock response
    res.json({
      error: 'Payment integration not implemented yet',
      message: 'This feature is under development',
    });
  })
);

export default router;
