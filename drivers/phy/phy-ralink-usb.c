/*
 * Allwinner ralink USB phy driver
 *
 * Copyright (C) 2014 John Crispin <blogic@openwrt.org>
 *
 * Based on code from
 * Allwinner Technology Co., Ltd. <www.allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/of_platform.h>

#include <asm/mach-ralink/ralink_regs.h>

#define RT_SYSC_REG_SYSCFG1		0x014
#define RT_SYSC_REG_CLKCFG1		0x030
#define RT_SYSC_REG_USB_PHY_CFG		0x05c

#define RT_RSTCTRL_UDEV			BIT(25)
#define RT_RSTCTRL_UHST			BIT(22)
#define RT_SYSCFG1_USB0_HOST_MODE	BIT(10)

#define MT7620_CLKCFG1_UPHY0_CLK_EN	BIT(25)
#define MT7620_CLKCFG1_UPHY1_CLK_EN	BIT(22)
#define RT_CLKCFG1_UPHY1_CLK_EN		BIT(20)
#define RT_CLKCFG1_UPHY0_CLK_EN		BIT(18)

#define USB_PHY_UTMI_8B60M		BIT(1)
#define UDEV_WAKEUP			BIT(0)

static atomic_t usb_pwr_ref = ATOMIC_INIT(0);
static struct reset_control *rstdev;
static struct reset_control *rsthost;
static u32 phy_clk;
static struct phy *rt_phy;

static void usb_phy_enable(int state)
{
	if (state)
		rt_sysc_m32(0, phy_clk, RT_SYSC_REG_CLKCFG1);
	else
		rt_sysc_m32(phy_clk, 0, RT_SYSC_REG_CLKCFG1);
	mdelay(100);
}

static int ralink_usb_phy_init(struct phy *_phy)
{
	return 0;
}

static int ralink_usb_phy_exit(struct phy *_phy)
{
	return 0;
}

static int ralink_usb_phy_power_on(struct phy *_phy)
{
	if (atomic_inc_return(&usb_pwr_ref) == 1) {
		int host = 1;
		u32 t;

		usb_phy_enable(1);

		if (host) {
			rt_sysc_m32(0, RT_SYSCFG1_USB0_HOST_MODE, RT_SYSC_REG_SYSCFG1);
			if (!IS_ERR(rsthost))
				reset_control_deassert(rsthost);
			if (!IS_ERR(rstdev))
				reset_control_deassert(rstdev);
		} else {
			rt_sysc_m32(RT_SYSCFG1_USB0_HOST_MODE, 0, RT_SYSC_REG_SYSCFG1);
			if (!IS_ERR(rstdev))
				reset_control_deassert(rstdev);
		}
		mdelay(100);

		t = rt_sysc_r32(RT_SYSC_REG_USB_PHY_CFG);
		dev_info(&_phy->dev, "remote usb device wakeup %s\n",
			(t & UDEV_WAKEUP) ? ("enabbled") : ("disabled"));
		if (t & USB_PHY_UTMI_8B60M)
			dev_info(&_phy->dev, "UTMI 8bit 60MHz\n");
		else
			dev_info(&_phy->dev, "UTMI 16bit 30MHz\n");
	}

	return 0;
}

static int ralink_usb_phy_power_off(struct phy *_phy)
{
	if (atomic_dec_return(&usb_pwr_ref) == 0) {
		usb_phy_enable(0);
		if (!IS_ERR(rstdev))
			reset_control_assert(rstdev);
		if (!IS_ERR(rsthost))
			reset_control_assert(rsthost);
	}

	return 0;
}

static struct phy_ops ralink_usb_phy_ops = {
	.init		= ralink_usb_phy_init,
	.exit		= ralink_usb_phy_exit,
	.power_on	= ralink_usb_phy_power_on,
	.power_off	= ralink_usb_phy_power_off,
	.owner		= THIS_MODULE,
};

static struct phy *ralink_usb_phy_xlate(struct device *dev,
					struct of_phandle_args *args)
{
	return rt_phy;
}

static const struct of_device_id ralink_usb_phy_of_match[] = {
	{ .compatible = "ralink,rt3xxx-usbphy", .data = (void *) (RT_CLKCFG1_UPHY1_CLK_EN | RT_CLKCFG1_UPHY0_CLK_EN) },
	{ .compatible = "ralink,mt7620a-usbphy", .data = (void *) (MT7620_CLKCFG1_UPHY1_CLK_EN | MT7620_CLKCFG1_UPHY0_CLK_EN) },
	{ },
};
MODULE_DEVICE_TABLE(of, ralink_usb_phy_of_match);

static int ralink_usb_phy_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct phy_provider *phy_provider;
	const struct of_device_id *match;

	printk("%s:%s[%d]\n", __FILE__, __func__, __LINE__);
	match = of_match_device(ralink_usb_phy_of_match, &pdev->dev);
	phy_clk = (int) match->data;

	rsthost = devm_reset_control_get(&pdev->dev, "host");
	rstdev = devm_reset_control_get(&pdev->dev, "device");

	rt_phy = devm_phy_create(dev, NULL, &ralink_usb_phy_ops, NULL);
	if (IS_ERR(rt_phy)) {
		dev_err(dev, "failed to create PHY\n");
		return PTR_ERR(rt_phy);
	}

	phy_provider = devm_of_phy_provider_register(dev, ralink_usb_phy_xlate);
printk("%s:%s[%d]\n", __FILE__, __func__, __LINE__);

	return PTR_ERR_OR_ZERO(phy_provider);
}

static struct platform_driver ralink_usb_phy_driver = {
	.probe	= ralink_usb_phy_probe,
	.driver = {
		.of_match_table	= ralink_usb_phy_of_match,
		.name  = "ralink-usb-phy",
	}
};
module_platform_driver(ralink_usb_phy_driver);

MODULE_DESCRIPTION("Ralink USB phy driver");
MODULE_AUTHOR("John Crispin <blogic@openwrt.org>");
MODULE_LICENSE("GPL v2");
