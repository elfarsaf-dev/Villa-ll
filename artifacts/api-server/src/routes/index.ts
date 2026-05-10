import { Router, type IRouter } from "express";
import healthRouter from "./health.js";
import villaRouter from "./villa.js";

const router: IRouter = Router();

router.use(healthRouter);
router.use(villaRouter);

export default router;
