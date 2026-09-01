
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ShoppingCart, Package } from "lucide-react";
import Image from "next/image";

type Product = {
  id: string;
  name: string;
  description: string;
  price: number;
  imageUrl: string;
  stock: number;
};

const products: Product[] = [
  {
    id: "PROD-001",
    name: "Enterprise SSD 2TB",
    description: "High-speed NVMe SSD for data centers.",
    price: 399.99,
    imageUrl: "https://picsum.photos/seed/ssd/100/100",
    stock: 1500,
  },
  {
    id: "PROD-002",
    name: "Enterprise HDD 16TB",
    description: "High-capacity SATA HDD for bulk storage.",
    price: 450.00,
    imageUrl: "https://picsum.photos/seed/hdd/100/100",
    stock: 800,
  },
  {
    id: "PROD-003",
    name: "Secure USB Drive 256GB",
    description: "FIPS 140-2 Level 3 validated secure flash drive.",
    price: 129.50,
    imageUrl: "https://picsum.photos/seed/usb/100/100",
    stock: 3000,
  },
  {
    id: "PROD-004",
    name: "Data Destruction Appliance",
    description: "On-premise hardware for certified data erasure.",
    price: 7500.00,
    imageUrl: "https://picsum.photos/seed/appliance/100/100",
    stock: 50,
  },
];


export default async function ShopPage() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Package className="h-6 w-6" />
          Bulk IT Hardware Shop
        </CardTitle>
        <CardDescription>
          Place bulk orders for enterprise-grade hardware.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[120px]">Product</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="text-right">Unit Price</TableHead>
              <TableHead className="text-center w-[120px]">In Stock</TableHead>
              <TableHead className="w-[100px]">Quantity</TableHead>
              <TableHead className="w-[150px]">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {products.map((product) => (
              <TableRow key={product.id}>
                <TableCell>
                    <Image
                        src={product.imageUrl}
                        alt={product.name}
                        width={80}
                        height={80}
                        className="rounded-md"
                        data-ai-hint="product image"
                    />
                </TableCell>
                <TableCell>
                  <div className="font-medium">{product.name}</div>
                  <div className="text-sm text-muted-foreground">{product.description}</div>
                </TableCell>
                <TableCell className="text-right font-mono">${product.price.toFixed(2)}</TableCell>
                <TableCell className="text-center font-medium">{product.stock.toLocaleString()}</TableCell>
                <TableCell>
                    <Input type="number" defaultValue="1" min="1" className="w-20 text-center" />
                </TableCell>
                <TableCell>
                  <Button className="w-full">
                    <ShoppingCart className="mr-2 h-4 w-4" />
                    Add to Cart
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
